import re

class TextParser:
    def parse(self, content):
        """
        Parses text content and extracts potential IOCs using regex.
        Yields dicts with 'indicator' and 'type'.
        """
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'url': r'https?://[^\s,"\']+',
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'domain': r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        }

        # Priorities: URL > Email > IP/Hash > Domain
        # We'll just scan content.
        
        # To avoid overlapping matches (like IP inside URL), we can just find all and let validation/dedup handle it?
        # Or just yield everything found.
        # The prompt says "Extract". Validation comes later.
        
        extracted = []
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            for m in matches:
                # Basic filter to ensure domain isn't part of email/url if we were strict,
                # but for this assignment, finding them is enough.
                # However, domain regex matches IPs too often if not careful.
                # The domain regex above requires a dot and letters.
                
                # We simply yield all matches.
                yield {'indicator': m, 'type': ioc_type}
