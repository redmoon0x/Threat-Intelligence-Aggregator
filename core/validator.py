import ipaddress
import re

class Validator:
    def validate(self, item):
        """
        Validates the IOC item.
        Returns the item if valid, else None.
        """
        indicator = item.get('indicator')
        ioc_type = item.get('type')

        if not indicator:
            return None
        
        # Normalize type string
        if ioc_type:
            ioc_type = ioc_type.lower()
        else:
            # If no type, we might try to infer or just fail? 
            # Requirements said "Extract ... IOC types".
            # If parser found it, it probably has a type.
            return None

        try:
            if ioc_type == 'ip':
                try:
                    ipaddress.ip_address(indicator)
                    return item
                except ValueError:
                    return None
            
            elif ioc_type == 'domain':
                # Basic domain validation
                if len(indicator) > 255:
                    return None
                if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', indicator):
                    return item
                return None
            
            elif ioc_type == 'url':
                if re.match(r'^https?://[^\s/$.?#].[^\s]*$', indicator):
                    return item
                return None

            elif ioc_type in ['md5', 'sha1', 'sha256', 'hash']:
                length = len(indicator)
                if length == 32: # MD5
                     item['type'] = 'md5'
                     if re.match(r'^[a-fA-F0-9]{32}$', indicator): return item
                elif length == 40: # SHA1
                     item['type'] = 'sha1'
                     if re.match(r'^[a-fA-F0-9]{40}$', indicator): return item
                elif length == 64: # SHA256
                     item['type'] = 'sha256'
                     if re.match(r'^[a-fA-F0-9]{64}$', indicator): return item
                return None
            
            elif ioc_type == 'email':
                 if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', indicator):
                     return item
                 return None

            else:
                # Unknown type - valid?
                # "Discard invalid indicators silently"
                # If we don't know the type, is it invalid?
                # We'll assume yes to be safe.
                return None

        except Exception:
            return None
