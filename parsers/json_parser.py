import json

class JsonParser:
    def parse(self, content):
        """
        Parses JSON content. Expects a list of objects with 'indicator' and 'type'.
        """
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        indicator = item.get('indicator') or item.get('ioc')
                        ioc_type = item.get('type')
                        if indicator:
                            yield {'indicator': indicator, 'type': ioc_type}
            elif isinstance(data, dict):
                 # Handle single object
                indicator = data.get('indicator') or data.get('ioc')
                ioc_type = data.get('type')
                if indicator:
                    yield {'indicator': indicator, 'type': ioc_type}

        except Exception as e:
            print(f"Error parsing JSON: {e}")
            return []
