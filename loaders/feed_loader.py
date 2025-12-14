import os
import requests

class FeedLoader:
    def load(self, source):
        """
        Loads content from a file path or URL.
        Returns a tuple: (content, source_type)
        source_type is 'file' or 'url'
        """
        if source.startswith('http://') or source.startswith('https://'):
            try:
                response = requests.get(source, timeout=10)
                response.raise_for_status()
                return response.text
            except requests.RequestException as e:
                print(f"Error fetching URL {source}: {e}")
                return None
        else:
            if os.path.exists(source):
                try:
                    with open(source, 'r', encoding='utf-8') as f:
                        return f.read()
                except Exception as e:
                    print(f"Error reading file {source}: {e}")
                    return None
            else:
                print(f"File not found: {source}")
                return None
