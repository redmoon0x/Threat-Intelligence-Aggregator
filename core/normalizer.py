from datetime import datetime

class Normalizer:
    def normalize(self, item, source):
        """
        Converts IOC into strict structure:
        {
          indicator: str,
          type: str,
          source: str,
          first_seen: datetime,
        }
        """
        return {
            'indicator': item['indicator'],
            'type': item['type'],
            'source': source,
            'first_seen': datetime.now() 
        }
