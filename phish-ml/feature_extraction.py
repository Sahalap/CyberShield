import os
import re
import pandas as pd
import logging
from urllib.parse import urlparse
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO)

# Paths
DATA_DIR = "data"
OPENPHISH_FILE = os.path.join(DATA_DIR, "openphish_urls.csv")
PHISHING_AGGREGATED_FILE = os.path.join(DATA_DIR, "phishing_urls_aggregated.csv")
TRANCO_FILE = os.path.join(DATA_DIR, "tranco_top_sites.csv")
OUTPUT_FILE = os.path.join(DATA_DIR, "url_features.csv")

# Inline augmentations to better learn WhatsApp-style phishing without new files
# Labels: 1 = phishing, 0 = legitimate
EXTRA_PHISHING_URLS = [
    # User-reported misses
    'https://wa.me/verify-account',
    'https://chat.whatsapp.com/fake-security',
    'https://suspicious-test.tk',
    # Variations to generalize patterns
    'http://wa.me/verify-account',
    'https://wa.me/verification',
    'https://chat.whatsapp.com/security-update',
    'https://chat.whatsapp.com/fake-giveaway',
    'https://paypal-security.tk',
    'https://whatsapp-verify.tk',
    'https://google-account-suspended.tk',
    # More TK domain examples
    'https://amazon-verify.tk',
    'https://microsoft-security.ml',
    'https://apple-suspended.ga',
    # URL shortener phishing
    'https://bit.ly/paypal-verify123',
    'https://tinyurl.com/amazon-suspend',
    # IP-based phishing
    'http://192.168.1.100/paypal-login',
    'https://123.456.789.012/microsoft-verify',
    # @ symbol phishing
    'https://google.com@malicious-site.com/login',
    'https://paypal.com@phishing-site.tk/secure'
]

EXTRA_BENIGN_URLS = [
    # Known legitimate WhatsApp endpoints
    'https://web.whatsapp.com',
    'https://whatsapp.com',
    'https://api.whatsapp.com',
    'https://whatsapp.com/security',
    'https://web.whatsapp.com/download',
    'https://faq.whatsapp.com/help',
    
    # AI & Developer Tools (commonly flagged)
    'https://chatgpt.com',
    'https://chat.openai.com',
    'https://platform.openai.com',
    'https://openai.com',
    'https://api.openai.com',
    'https://claude.ai',
    'https://anthropic.com',
    'https://cursor.sh',
    'https://github.com',
    'https://github.com/trending',
    'https://gist.github.com',
    'https://raw.githubusercontent.com',
    'https://gitlab.com',
    'https://bitbucket.org',
    'https://stackoverflow.com',
    'https://stackexchange.com',
    'https://npmjs.com',
    'https://pypi.org',
    
    # Google Services (LOTS of them - most visited)
    'https://google.com',
    'https://www.google.com/search',
    'https://gmail.com',
    'https://mail.google.com',
    'https://drive.google.com',
    'https://docs.google.com',
    'https://meet.google.com',
    'https://calendar.google.com',
    'https://maps.google.com',
    'https://youtube.com',
    'https://accounts.google.com',
    'https://accounts.google.com/signin',
    'https://myaccount.google.com',
    
    # Microsoft Services
    'https://microsoft.com',
    'https://outlook.com',
    'https://office.com',
    'https://login.microsoftonline.com',
    'https://teams.microsoft.com',
    'https://onedrive.live.com',
    
    # Social Media
    'https://wikipedia.org',
    'https://reddit.com',
    'https://www.reddit.com',
    'https://linkedin.com',
    'https://twitter.com',
    'https://x.com',
    'https://facebook.com',
    'https://www.facebook.com',
    'https://instagram.com',
    'https://tiktok.com',
    'https://pinterest.com',
    
    # Streaming & Entertainment
    'https://netflix.com',
    'https://www.netflix.com',
    'https://spotify.com',
    'https://twitch.tv',
    'https://discord.com',
    'https://vimeo.com',
    
    # E-commerce
    'https://amazon.com',
    'https://www.amazon.com',
    'https://ebay.com',
    'https://etsy.com',
    
    # Financial Services
    'https://paypal.com',
    'https://www.paypal.com',
    'https://stripe.com',
    'https://wise.com',
    'https://www.wise.com',
    'https://transferwise.com',
    'https://wise.com/in/currency-converter/usd-to-inr-rate',
    
    # Cloud & Productivity
    'https://dropbox.com',
    'https://slack.com',
    'https://zoom.us',
    'https://notion.so',
    'https://figma.com',
    'https://canva.com',
    'https://trello.com',
    
    # CDNs & Infrastructure (IMPORTANT - often flagged)
    'https://cloudflare.com',
    'https://cdn.jsdelivr.net',
    'https://unpkg.com',
    'https://cdnjs.cloudflare.com',
    
    # Legitimate sites with "security" in path (should NOT be flagged)
    'https://support.google.com/accounts/answer/security',
    'https://www.microsoft.com/en-us/security',
    'https://support.apple.com/en-us/HT201232',
    'https://www.paypal.com/us/smarthelp/article/security',
    'https://help.netflix.com/en/node/account-security',
    'https://security.google.com',
    'https://transparency.fb.com/data/government-data-requests/',
    
    # Legitimate sites with "verify" or "confirm" in path
    'https://accounts.google.com/signin/v2/identifier',
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://www.paypal.com/signin/verify',
    'https://appleid.apple.com/account/manage',
    
    # Auth/Login pages (commonly visited)
    'https://login.live.com',
    'https://login.yahoo.com',
    'https://signin.ebay.com',
    'https://secure.netflix.com',
    
    # Legitimate numeric/subdomain patterns
    'https://web2.outlook.com',
    'https://drive2.google.com',
    'https://app2.slack.com',
    'https://cdn1.example.com',
    'https://api1.github.com',
    
    # News Sites
    'https://cnn.com',
    'https://bbc.com',
    'https://nytimes.com',
    'https://theguardian.com',
    'https://reuters.com',
    
    # More popular sites users visit daily
    'https://wordpress.com',
    'https://medium.com',
    'https://tumblr.com',
    'https://quora.com',
    'https://yelp.com',
    'https://imdb.com',
    
    # Educational institutions (CRITICAL - never block!)
    'https://ktu.edu.in',
    'https://ktu.ac.in',
    'https://mit.edu',
    'https://stanford.edu',
    'https://harvard.edu',
    'https://berkeley.edu',
    'https://oxford.ac.uk',
    'https://cambridge.ac.uk',
    'https://coursera.org',
    'https://edx.org',
    'https://udemy.com',
    'https://khanacademy.org',
    
    # University login pages (commonly flagged)
    'https://login.university.edu',
    'https://portal.university.edu',
    'https://student.university.edu',
    'https://sso.university.edu'
]

class URLFeatureExtractor:
    def __init__(self):
        # Only highly suspicious TLDs used primarily for spam/phishing
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.loan', '.win', '.bid']
        
        # FIXED: More specific brand patterns that avoid legitimate matches
        # Only match when NOT part of legitimate domain
        self.brand_keywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 
                               'facebook', 'netflix', 'whatsapp', 'instagram']
        
        # Comprehensive whitelist of legitimate domains
        self.legitimate_domains = {
            # Major tech companies
            'google.com', 'youtube.com', 'gmail.com', 'gstatic.com', 'googleapis.com',
            'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com',
            'apple.com', 'icloud.com', 'apple.co',
            'amazon.com', 'amazonaws.com', 'aws.amazon.com',
            'facebook.com', 'fb.com', 'fbcdn.net',
            'twitter.com', 'x.com', 't.co',
            'linkedin.com',
            'instagram.com',
            'netflix.com',
            'paypal.com',
            'stripe.com',
            
            # Communication platforms
            'whatsapp.com', 'wa.me',
            'slack.com',
            'zoom.us',
            'discord.com',
            'telegram.org',
            
            # Development & Tech
            'github.com', 'gitlab.com', 'bitbucket.org',
            'stackoverflow.com', 'stackexchange.com',
            'openai.com', 'chatgpt.com', 'chat.openai.com', 'platform.openai.com',
            'api.openai.com', 'auth0.openai.com', 'cdn.openai.com',
            'anthropic.com', 'claude.ai', 'console.anthropic.com',
            'npmjs.com', 'pypi.org',
            'cursor.sh', 'cursor.com',
            
            # Educational & Tutorial Sites (CRITICAL - never block!)
            'geeksforgeeks.org',
            'w3schools.com',
            'tutorialspoint.com',
            'javatpoint.com',
            'programiz.com',
            'codecademy.com',
            'freecodecamp.org',
            'udemy.com',
            'coursera.org',
            'khanacademy.org',
            'edx.org',
            'leetcode.com',
            'hackerrank.com',
            'datacamp.com',
            'etlab.app',
            
            # Content & Social
            'reddit.com', 'redd.it',
            'wikipedia.org', 'wikimedia.org',
            'medium.com',
            'tumblr.com',
            'pinterest.com',
            'tiktok.com',
            
            # Other major sites
            'dropbox.com',
            'adobe.com',
            'cloudflare.com',
            'godaddy.com',
            'wordpress.com', 'wordpress.org',
            'blogger.com',
            'notion.so',
            'figma.com',
            'canva.com',
            
            # Fintech & Currency Exchange (NEVER block!)
            'wise.com', 'transferwise.com',
            'revolut.com',
            'xe.com', 'oanda.com',
            'payoneer.com',
            
            # Data Science & Learning
            'kaggle.com',
            
            # Government & Official sites (NEVER block!)
            'ftc.gov', 'consumer.ftc.gov',
            'nih.gov', 'cdc.gov', 'irs.gov', 'ssa.gov',
            'usa.gov', 'whitehouse.gov', 'nasa.gov'
        }
        
        # URL shorteners (legitimate but need careful handling)
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
            'short.link', 'is.gd', 'v.gd', 'cutt.ly', 'shorturl.at'
        }
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract features from a single URL with error handling"""
        try:
            if not url or not isinstance(url, str):
                return self._get_default_features()
            
            parsed = urlparse(url)
            if not parsed.netloc:
                return self._get_default_features()
            
            hostname = parsed.netloc.lower()
            full_url = url.lower()
            
            # Basic URL features - LESS AGGRESSIVE: Cap extreme values
            features = {
                "url_length": min(len(url), 150),  # Cap at 150 to reduce impact of very long URLs
                "num_dots": min(url.count('.'), 5),  # Cap at 5
                "num_hyphens": min(url.count('-'), 5),  # Cap at 5 (legitimate sites can have many)
                "num_digits": min(sum(c.isdigit() for c in url), 10),  # Cap at 10
                "has_at_symbol": 1 if "@" in url else 0,
                "num_params": min(url.count('='), 5),  # Cap at 5 (currency converters have params)
                "has_ip": self._has_ip_address(hostname),
                "is_https": 1 if parsed.scheme == "https" else 0,
                "path_length": min(len(parsed.path), 100),  # Cap at 100
                "domain_length": min(len(parsed.netloc), 50),  # Cap at 50
            }
            
            # FIXED: Only flag if truly suspicious
            features["has_brand_spoofing"] = self._detect_brand_spoofing(hostname, full_url)
            features["has_suspicious_tld"] = self._detect_suspicious_tld(hostname)
            features["has_character_substitution"] = self._detect_character_substitution(hostname)
            features["has_suspicious_keywords"] = self._detect_suspicious_keywords(full_url, hostname)
            
            # NEW: Additional discriminative features
            features["is_url_shortener"] = self._is_url_shortener(hostname)
            features["excessive_subdomains"] = self._has_excessive_subdomains(hostname)
            # REMOVED: is_legitimate_domain - whitelist should NOT be ML feature!
            # Whitelist is used as POST-PROCESSING safety check, not for ML training
            features["suspicious_keyword_combo"] = self._detect_suspicious_keyword_combinations(full_url, hostname)
            
            return features
        except Exception as e:
            logging.error(f"Error extracting features from {url}: {e}")
            return self._get_default_features()
    
    def _has_ip_address(self, hostname: str) -> int:
        """Check if URL contains IP address"""
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        return 1 if re.match(ip_pattern, hostname) else 0
    
    def _get_default_features(self) -> Dict[str, Any]:
        """Return default features for error cases"""
        return {
            "url_length": 0,
            "num_dots": 0,
            "num_hyphens": 0,
            "num_digits": 0,
            "has_at_symbol": 0,
            "num_params": 0,
            "has_ip": 0,
            "is_https": 0,
            "path_length": 0,
            "domain_length": 0,
            "has_brand_spoofing": 0,
            "has_suspicious_tld": 0,
            "has_character_substitution": 0,
            "has_suspicious_keywords": 0,
            "is_url_shortener": 0,
            "excessive_subdomains": 0,
            # REMOVED: is_legitimate_domain - not an ML feature anymore
            "suspicious_keyword_combo": 0,
        }
    
    def _is_legitimate_domain(self, hostname: str) -> int:
        """Check if domain is in whitelist of legitimate sites"""
        # Remove www. prefix
        hostname_clean = hostname.replace('www.', '')
        
        # Check exact match
        if hostname_clean in self.legitimate_domains:
            return 1
        
        # Check if it's a subdomain of a legitimate domain
        for domain in self.legitimate_domains:
            if hostname_clean == domain or hostname_clean.endswith('.' + domain):
                return 1
        
        return 0
    
    def _detect_brand_spoofing(self, hostname: str, full_url: str) -> int:
        """
        FIXED: Detect brand spoofing patterns - only flag obvious impersonation
        Must have brand keyword in hostname but NOT be the legitimate domain
        """
        # If it's a legitimate domain, it's NOT spoofing
        if self._is_legitimate_domain(hostname):
            return 0
        
        # Check if hostname contains brand keywords but is NOT the legitimate domain
        for brand in self.brand_keywords:
            # Must have the brand name in the hostname
            if brand in hostname:
                # Check if it's actually the legitimate brand domain
                legitimate_brand_domains = {
                    'paypal': ['paypal.com'],
                    'amazon': ['amazon.com', 'amazonaws.com'],
                    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
                    'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
                    'apple': ['apple.com', 'icloud.com'],
                    'facebook': ['facebook.com', 'fb.com'],
                    'netflix': ['netflix.com'],
                    'whatsapp': ['whatsapp.com', 'wa.me'],
                    'instagram': ['instagram.com']
                }
                
                # If brand has legitimate domains, check if this matches
                if brand in legitimate_brand_domains:
                    is_legitimate = False
                    for legit_domain in legitimate_brand_domains[brand]:
                        if hostname == legit_domain or hostname.endswith('.' + legit_domain):
                            is_legitimate = True
                            break
                    
                    # If it contains the brand but isn't the legitimate domain, it's spoofing
                    if not is_legitimate:
                        # Additional check: must have suspicious indicators
                        # (to avoid flagging legitimate news sites mentioning brands)
                        suspicious_indicators = [
                            '-' + brand,  # amazon-security.com
                            brand + '-',  # paypal-verify.com
                            brand + 'security',  # paylpalsecurity.com (typo)
                            brand + 'verify',
                            brand + 'suspended',
                            brand + 'alert'
                        ]
                        
                        if any(indicator in hostname for indicator in suspicious_indicators):
                            return 1
                        
                        # Also check for suspicious TLDs with brand
                        if self._detect_suspicious_tld(hostname):
                            return 1
        
        return 0
    
    def _detect_suspicious_tld(self, hostname: str) -> int:
        """Detect suspicious TLDs"""
        for tld in self.suspicious_tlds:
            if hostname.endswith(tld):
                return 1
        return 0
    
    def _detect_character_substitution(self, hostname: str) -> int:
        """
        FIXED: Detect character substitution patterns - more specific
        Only flag obvious substitutions, not normal numeric subdomains or legitimate words
        """
        # If it's a legitimate domain, no substitution
        if self._is_legitimate_domain(hostname):
            return 0
        
        # Remove legitimate numeric prefixes (web2, app2, etc.)
        if re.match(r'^(web|app|mail|cdn|api|server|host|node)\d+\.', hostname):
            return 0
        
        # Check domain part only (not subdomains)
        domain_parts = hostname.split('.')
        if len(domain_parts) < 2:
            return 0
        
        main_domain = domain_parts[-2]  # e.g., 'google' from 'mail.google.com'
        
        # CRITICAL FIX: More specific patterns that avoid false positives
        # Look for OBVIOUS substitution patterns only
        suspicious_patterns = [
            r'p[a4@]yp[a4@]l',      # paypal variations: p4ypal, p@ypal
            r'g[o0@]{2}gle',         # google variations: g00gle, g0ogle
            r'micr[o0]s[o0]ft',     # microsoft variations: micr0soft
            r'[a-z]+[0]{2,}[a-z]+',  # Multiple zeros: go00gle
            r'[a-z]+[4]{2,}[a-z]+',  # Multiple 4s: am4z4n
            r'fac[e3]b[o0]{2}k',    # facebook variations
            r'n[e3]tfl[i1]x',       # netflix variations
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, main_domain, re.IGNORECASE):
                return 1
        
        return 0
    
    def _detect_suspicious_keywords(self, full_url: str, hostname: str) -> int:
        """
        FIXED: Detect suspicious keywords - require context, not just presence
        Only flag if keyword appears in suspicious context
        """
        # If it's a legitimate domain, keywords in path are normal (e.g., google.com/security)
        if self._is_legitimate_domain(hostname):
            return 0
        
        # Define keywords that are suspicious in domain names but not paths of legitimate sites
        domain_suspicious_keywords = [
            'verify', 'suspended', 'locked', 'urgent', 'alert', 
            'warning', 'confirm', 'validate', 'fake', 'deal'
        ]
        
        # Check if suspicious keywords appear in the HOSTNAME (not just path)
        for keyword in domain_suspicious_keywords:
            if keyword in hostname:
                return 1
        
        # For suspicious keywords in path, require combination with other signals
        path_suspicious_keywords = ['suspend', 'locked', 'urgent', 'immediate']
        path = full_url.split(hostname)[-1] if hostname in full_url else ''
        
        keyword_in_path = any(keyword in path for keyword in path_suspicious_keywords)
        
        # Only flag path keywords if domain is also suspicious
        if keyword_in_path:
            if (self._detect_suspicious_tld(hostname) or 
                self._has_ip_address(hostname) or
                '@' in full_url):
                return 1
        
        return 0
    
    def _is_url_shortener(self, hostname: str) -> int:
        """Check if URL uses a shortener service"""
        hostname_clean = hostname.replace('www.', '')
        return 1 if hostname_clean in self.url_shorteners else 0
    
    def _has_excessive_subdomains(self, hostname: str) -> int:
        """Check for excessive number of subdomains (common in phishing)"""
        parts = hostname.split('.')
        # LESS AGGRESSIVE: More than 5 parts (legitimate sites often have 3-4)
        # e.g., login.secure.bank.example.com = 5 parts (still OK)
        return 1 if len(parts) > 5 else 0
    
    def _detect_suspicious_keyword_combinations(self, full_url: str, hostname: str) -> int:
        """
        NEW: Detect combinations of keywords that are highly indicative of phishing
        This is more specific than individual keyword detection
        """
        # If legitimate domain, return 0
        if self._is_legitimate_domain(hostname):
            return 0
        
        # Define keyword combinations (brand + action)
        brand_action_combos = [
            ('paypal', 'verify'),
            ('paypal', 'security'),
            ('paypal', 'suspended'),
            ('amazon', 'verify'),
            ('amazon', 'suspended'),
            ('amazon', 'update'),
            ('microsoft', 'security'),
            ('microsoft', 'verify'),
            ('google', 'verify'),
            ('google', 'suspended'),
            ('apple', 'verify'),
            ('whatsapp', 'verify'),
            ('whatsapp', 'suspended'),
            ('whatsapp', 'banned'),
            ('account', 'suspended'),
            ('account', 'locked'),
            ('security', 'alert'),
            ('urgent', 'verify'),
            ('confirm', 'identity')
        ]
        
        # Check if any combination exists in the URL
        for brand, action in brand_action_combos:
            if brand in full_url and action in full_url:
                return 1
        
        return 0

def process_urls_batch(urls: List[str], labels: List[int]) -> pd.DataFrame:
    """Process URLs in batches to avoid memory issues"""
    extractor = URLFeatureExtractor()
    features_list = []
    
    for i, url in enumerate(urls):
        if i % 1000 == 0:
            logging.info(f"Processed {i}/{len(urls)} URLs")
        
        features = extractor.extract_features(url)
        features['label'] = labels[i]
        features_list.append(features)
    
    return pd.DataFrame(features_list)

def extract_features(urls):
    """Original function for compatibility"""
    extractor = URLFeatureExtractor()
    features_list = []
    
    for url in urls:
        features = extractor.extract_features(url)
        features_list.append(features)
    
    return pd.DataFrame(features_list)

def main():
    """Main function with proper error handling - USE ALL AVAILABLE DATA"""
    try:
        logging.info("="*60)
        logging.info("LOADING ALL AVAILABLE DATASETS")
        logging.info("="*60)
        
        phishing_urls = []
        benign_urls = []
        
        # Load from COMBINED file if it exists (most efficient)
        combined_file = os.path.join(DATA_DIR, "combined_urls.csv")
        if os.path.exists(combined_file):
            logging.info(f"✅ Loading from combined dataset: {combined_file}")
            df = pd.read_csv(combined_file)
            
            # Separate phishing and legitimate
            phishing_df = df[df['label'] == 'phishing']
            legit_df = df[df['label'] == 'legit']
            
            phishing_urls = phishing_df['url'].tolist()
            benign_urls = legit_df['url'].tolist()
            
            logging.info(f"  📊 Phishing URLs from combined: {len(phishing_urls)}")
            logging.info(f"  📊 Legitimate URLs from combined: {len(benign_urls)}")
        else:
            logging.info("⚠️ Combined file not found, loading from individual files...")
            
            # Load all phishing sources
            phishing_files = [
                ("openphish_urls.csv", "OpenPhish"),
                ("urlhaus_urls.csv", "URLhaus"),
                ("phishing_database_urls.csv", "Phishing Database"),
                ("phishing_urls_aggregated.csv", "Aggregated")
            ]
            
            for filename, source in phishing_files:
                filepath = os.path.join(DATA_DIR, filename)
                if os.path.exists(filepath):
                    try:
                        df = pd.read_csv(filepath)
                        urls = df['url'].dropna().tolist()
                        phishing_urls.extend(urls)
                        logging.info(f"  ✅ {source}: {len(urls)} URLs")
                    except Exception as e:
                        logging.warning(f"  ⚠️ Could not load {filename}: {e}")
            
            # Remove duplicates
            phishing_urls = list(set(phishing_urls))
            logging.info(f"  📊 Total unique phishing URLs: {len(phishing_urls)}")
            
            # Load legitimate URLs
            if os.path.exists(TRANCO_FILE):
                df = pd.read_csv(TRANCO_FILE)
                benign_urls = df['url'].dropna().tolist()
                logging.info(f"  ✅ Tranco: {len(benign_urls)} URLs")

        # Augment datasets with extra examples
        phishing_urls.extend(EXTRA_PHISHING_URLS)
        benign_urls.extend(EXTRA_BENIGN_URLS)
        
        # Remove duplicates
        phishing_urls = list(set(phishing_urls))
        benign_urls = list(set(benign_urls))
        
        logging.info("\n" + "="*60)
        logging.info("FINAL DATASET SIZES")
        logging.info("="*60)
        logging.info(f"🔴 Total phishing URLs: {len(phishing_urls):,}")
        logging.info(f"🟢 Total benign URLs: {len(benign_urls):,}")
        logging.info(f"📊 Total URLs to process: {len(phishing_urls) + len(benign_urls):,}")
        logging.info("="*60 + "\n")
        
        data = []
        total_urls = len(phishing_urls) + len(benign_urls)
        
        # Extract phishing features
        logging.info("\n🔴 Extracting PHISHING URL features...")
        logging.info(f"Processing {len(phishing_urls):,} phishing URLs...")
        for i, url in enumerate(phishing_urls):
            if i % 5000 == 0:
                progress = (i / len(phishing_urls)) * 100
                logging.info(f"  Progress: {i:,}/{len(phishing_urls):,} ({progress:.1f}%)")
            try:
                feats = extract_features([url]).iloc[0].to_dict()
                feats["label"] = 1
                data.append(feats)
            except Exception as e:
                if i % 1000 == 0:  # Only log errors occasionally
                    logging.warning(f"  Skipped URL {i} due to error: {str(e)[:50]}")

        logging.info(f"✅ Completed phishing features: {len([d for d in data if d['label']==1]):,} URLs")

        # Extract benign features
        logging.info("\n🟢 Extracting LEGITIMATE URL features...")
        logging.info(f"Processing {len(benign_urls):,} legitimate URLs...")
        for i, url in enumerate(benign_urls):
            if i % 5000 == 0:
                progress = (i / len(benign_urls)) * 100
                logging.info(f"  Progress: {i:,}/{len(benign_urls):,} ({progress:.1f}%)")
            try:
                feats = extract_features([url]).iloc[0].to_dict()
                feats["label"] = 0
                data.append(feats)
            except Exception as e:
                if i % 1000 == 0:  # Only log errors occasionally
                    logging.warning(f"  Skipped URL {i} due to error: {str(e)[:50]}")
        
        logging.info(f"✅ Completed legitimate features: {len([d for d in data if d['label']==0]):,} URLs")

        # Create dataframe and save
        logging.info("\n" + "="*60)
        logging.info("SAVING FEATURES TO FILE")
        logging.info("="*60)
        
        df = pd.DataFrame(data)
        df.to_csv(OUTPUT_FILE, index=False)
        
        logging.info(f"\n✅ Features extracted and saved to: {OUTPUT_FILE}")
        logging.info(f"📊 Total samples: {len(df):,}")
        logging.info(f"🔴 Phishing samples: {(df['label'] == 1).sum():,}")
        logging.info(f"🟢 Benign samples: {(df['label'] == 0).sum():,}")
        
        # Calculate file size
        file_size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
        logging.info(f"💾 File size: {file_size_mb:.1f} MB")
        
        # Show feature statistics
        logging.info("\n" + "="*60)
        logging.info("FEATURE STATISTICS")
        logging.info("="*60)
        print("\nFirst few rows:")
        print(df.head())
        print("\nDataset Balance:")
        print(df['label'].value_counts())
        print("\nFeature correlations with label:")
        print(df.corr()['label'].sort_values(ascending=False))
        
        logging.info("\n" + "="*60)
        logging.info("✅ FEATURE EXTRACTION COMPLETE!")
        logging.info("="*60)
        
    except Exception as e:
        logging.error(f"Error in main: {e}")
        raise

if __name__ == "__main__":
    main()