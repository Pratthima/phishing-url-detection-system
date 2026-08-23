import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    
    # Length features
    features['url_length'] = len(url)
    features['hostname_length'] = len(urlparse(url).hostname)
    
    # Count special characters
    features['count_dot'] = url.count('.')
    features['count_hyphen'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_slash'] = url.count('/')
    features['count_question'] = url.count('?')
    features['count_equal'] = url.count('=')
    features['count_digit'] = sum(c.isdigit() for c in url)
    
    # Suspicious words
    suspicious_words = ["secure", "account", "update", "free", "verify", "login", "bank"]
    features['contains_suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
    
    # Check IP address
    match_ip = re.search(r'\d+\.\d+\.\d+\.\d+', url)
    features['contains_ip'] = 1 if match_ip else 0
    
    return list(features.values())
import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    
    # Parse URL safely
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""
    
    # Length features
    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)
    
    # Count special characters
    features['count_dot'] = url.count('.')
    features['count_hyphen'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_slash'] = url.count('/')
    features['count_question'] = url.count('?')
    features['count_equal'] = url.count('=')
    features['count_digit'] = sum(c.isdigit() for c in url)
    
    # Suspicious words
    suspicious_words = ["secure", "account", "update", "free", "verify", "login", "bank"]
    features['contains_suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
    
    # Check IP address
    match_ip = re.search(r'\d+\.\d+\.\d+\.\d+', url)
    features['contains_ip'] = 1 if match_ip else 0
    
    return list(features.values())
