import csv
import io

class CsvParser:
    def parse(self, content):
        """
        Parses CSV content. Expects headers like 'indicator', 'type'.
        """
        try:
            f = io.StringIO(content)
            reader = csv.DictReader(f)
            for row in reader:
                # keys might be case-insensitive?
                # Normalize keys
                row_clean = {k.lower(): v for k, v in row.items() if k}
                
                indicator = row_clean.get('indicator') or row_clean.get('ioc')
                ioc_type = row_clean.get('type')
                
                if indicator:
                    yield {'indicator': indicator, 'type': ioc_type}
        except Exception as e:
            print(f"Error parsing CSV: {e}")
            return []
