import os
import glob
import sys
import argparse
import logging
from datetime import datetime

from loaders.feed_loader import FeedLoader
from parsers.csv_parser import CsvParser
from parsers.json_parser import JsonParser
from parsers.text_parser import TextParser
from core.validator import Validator
from core.normalizer import Normalizer
from core.correlator import Correlator

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ThreatAggregator")

class ThreatAggregator:
    def __init__(self, output_dir=None):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Output Directories
        if output_dir:
            self.output_base = output_dir
        else:
            self.output_base = os.path.join(self.base_dir, 'output')

        self.blocklist_dir = os.path.join(self.output_base, 'blocklists')
        self.report_dir = os.path.join(self.output_base, 'reports')
        
        # Ensure directories exist
        os.makedirs(self.blocklist_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

        # Components
        self.loader = FeedLoader()
        self.validator = Validator()
        self.normalizer = Normalizer()
        self.correlator = Correlator()
        
        self.parsers = {
            '.csv': CsvParser(),
            '.json': JsonParser(),
            '.txt': TextParser()
        }

    def process_feeds(self, input_path):
        """
        Discovers and processes feeds from the given input path (file or directory).
        """
        feed_files = self._discover_feeds(input_path)
        
        if not feed_files:
            logger.warning(f"No valid feed files found in: {input_path}")
            return

        logger.info(f"Starting processing of {len(feed_files)} feeds...")
        
        processed_count = 0
        for file_path in feed_files:
            if self._process_single_feed(file_path):
                processed_count += 1
        
        self._generate_outputs(processed_count)

    def _discover_feeds(self, input_path):
        """
        Returns a list of file paths to process.
        """
        feeds = []
        
        # Handle URL input (simple check)
        if input_path.startswith(('http://', 'https://')):
            # For this assignment, we treat a URL as a single "file" source
            # The loader handles the fetching, but we need a 'dummy' extension to choose a parser.
            # We'll try to guess or default to text if no extension.
            # However, the structure expects local file paths mostly for extension checking.
            # Let's support it via direct processing if needed, but the prompt implies file inputs mainly.
            # "feed should be given as input ... with path"
            # If the user passes a URL, we might need a strategy.
            # Let's assume input_path is local unless specified otherwise, but the Loader supports URLs.
            # We'll just append it and let the processor handle the 'ext' logic.
            feeds.append(input_path)
            return feeds

        if os.path.isfile(input_path):
            feeds.append(input_path)
        elif os.path.isdir(input_path):
            for ext in self.parsers.keys():
                found = glob.glob(os.path.join(input_path, f'*{ext}'))
                feeds.extend(found)
        else:
            logger.error(f"Input path does not exist: {input_path}")
        
        return feeds

    def _process_single_feed(self, source):
        logger.info(f"Processing source: {source}")
        
        try:
            content = self.loader.load(source)
            if not content:
                logger.warning(f"Skipping empty or inaccessible source: {source}")
                return False

            # Determine parser
            # If it's a file, use extension. If URL, try to guess or default to .txt parser?
            # For simplicity, we assume file extension logic or treat as .txt for URLs unless .json/.csv is in name.
            if source.startswith(('http://', 'https://')):
                if '.json' in source: ext = '.json'
                elif '.csv' in source: ext = '.csv'
                else: ext = '.txt'
            else:
                ext = os.path.splitext(source)[1].lower()

            parser = self.parsers.get(ext)
            if not parser:
                logger.warning(f"No parser available for extension: {ext}")
                return False

            count = 0
            for item in parser.parse(content):
                validated_item = self.validator.validate(item)
                if validated_item:
                    norm_item = self.normalizer.normalize(
                        validated_item, 
                        source=os.path.basename(source) if not source.startswith('http') else source
                    )
                    self.correlator.add_ioc(norm_item)
                    count += 1
            
            logger.debug(f"Extracted {count} valid IOCs from {source}")
            return True

        except Exception as e:
            logger.error(f"Failed to process {source}: {e}", exc_info=True)
            return False

    def _generate_outputs(self, processed_count):
        # Correlate
        results = self.correlator.correlate()
        total_unique = len(results)
        logger.info(f"Correlation complete. Total unique indicators: {total_unique}")

        # Segregate Data
        type_map = {
            'ip': 'ip', 'domain': 'domain', 'url': 'url',
            'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash', 'hash': 'hash'
        }
        
        blocklists = {k: [] for k in set(type_map.values())}
        type_counts = {}
        high_sev_count = 0

        for ioc in results:
            t = ioc.get('type')
            
            # Stats
            if ioc.get('severity') == 'High':
                high_sev_count += 1
            
            type_counts[t] = type_counts.get(t, 0) + 1
            
            # Blocklist Grouping
            category = type_map.get(t)
            if category:
                blocklists[category].append(ioc['indicator'])

        # Write Blocklists
        file_map = {
            'ip': 'firewall_ips.txt',
            'domain': 'malicious_domains.txt',
            'url': 'malicious_urls.txt',
            'hash': 'hash_blocklist.txt'
        }

        for cat, filename in file_map.items():
            if cat in blocklists:
                path = os.path.join(self.blocklist_dir, filename)
                self._write_file(path, blocklists[cat])

        # Write Report
        self._write_report(processed_count, total_unique, high_sev_count, type_counts)

    def _write_file(self, path, lines):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            logger.info(f"Generated: {path}")
        except IOError as e:
            logger.error(f"Error writing to {path}: {e}")

    def _write_report(self, processed_count, total_unique, high_sev_count, type_counts):
        report_lines = [
            "Threat Intelligence Aggregator Report",
            "=====================================",
            f"Generated at: {datetime.now()}",
            "",
            f"Total Feeds Processed: {processed_count}",
            f"Total Unique Indicators: {total_unique}",
            f"High-Severity Indicators: {high_sev_count}",
            "",
            "Breakdown by IOC Type:"
        ]
        
        for t, count in sorted(type_counts.items()):
            report_lines.append(f"  - {t}: {count}")

        report_path = os.path.join(self.report_dir, 'summary_report.txt')
        self._write_file(report_path, report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator - A Deterministic IOC Processor"
    )
    
    # Optional input argument
    parser.add_argument(
        '-f', '--feed',
        dest='feed_input',
        default=None,
        help="Path to a single feed file or directory containing feeds. Defaults to internal 'feeds/' directory."
    )

    args = parser.parse_args()

    # Default logic if no arg provided
    base_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = args.feed_input if args.feed_input else os.path.join(base_dir, 'feeds')
    
    aggregator = ThreatAggregator()
    
    try:
        aggregator.process_feeds(input_path)
        print("\n✅ Aggregation finished successfully.")
    except Exception as e:
        logger.critical(f"Fatal error during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
