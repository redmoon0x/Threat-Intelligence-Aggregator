import collections

class Correlator:
    def __init__(self):
        # Dictionary to store aggregated data
        # Key: (indicator, type) -> Value: object with count, sources, etc
        self.data = {}

    def add_ioc(self, normalized_ioc):
        key = (normalized_ioc['indicator'], normalized_ioc['type'])
        
        if key not in self.data:
            self.data[key] = {
                'indicator': normalized_ioc['indicator'],
                'type': normalized_ioc['type'],
                'first_seen': normalized_ioc['first_seen'],
                'count': 0,
                'sources': set()
            }
        
        self.data[key]['count'] += 1
        self.data[key]['sources'].add(normalized_ioc['source'])

    def correlate(self):
        """
        Finalizes severity scores.
        Returns a list of enriched IOC objects.
        """
        results = []
        for key, val in self.data.items():
            count = val['count']
            
            # Severity Logic
            if count >= 4:
                severity = 'High'
            elif count >= 2:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            val['severity'] = severity
            # Convert sources set to list for output/JSON serializability if needed
            val['sources'] = list(val['sources'])
            results.append(val)
            
        return results
