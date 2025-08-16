import json
import random
import time
import os
import pickle
from datetime import datetime, timedelta
from curl_cffi import requests

# List of supported impersonations in curl_cffi
SUPPORTED_IMPERSONATIONS = [
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107", "chrome110", 
    "chrome116", "chrome117", "chrome119", "chrome120",
    "chrome99_android", "safari15_3", "safari15_5", "safari17_0", 
    "safari17_2_ios", "safari17_3_ios", "safari17_4_ios", "safari17_4_1_ios"
]

class SessionManager:
    """Handles session persistence for browser profiles"""
    
    def __init__(self, session_dir="sessions"):
        self.session_dir = session_dir
        os.makedirs(session_dir, exist_ok=True)
    
    def get_session_file(self, profile_name):
        """Get path to session file for a profile"""
        return os.path.join(self.session_dir, f"{profile_name}.session")
    
    def save_session(self, profile_name, session_data):
        """Save session data for a profile"""
        session_file = self.get_session_file(profile_name)
        session_data['last_used'] = datetime.now().isoformat()
        with open(session_file, 'wb') as f:
            pickle.dump(session_data, f)
    
    def load_session(self, profile_name, max_age_hours=24):
        """Load session data for a profile if it exists and is not expired"""
        session_file = self.get_session_file(profile_name)
        if not os.path.exists(session_file):
            return None
            
        try:
            with open(session_file, 'rb') as f:
                session_data = pickle.load(f)
            
            # Check if session is expired
            last_used = datetime.fromisoformat(session_data.get('last_used', '1970-01-01'))
            if datetime.now() - last_used > timedelta(hours=max_age_hours):
                return None
                
            return session_data
        except Exception as e:
            print(f"Error loading session for {profile_name}: {e}")
            return None

class BrowserClient:
    def __init__(self, profile_name=None, proxy=None, session_manager=None):
        self.profiles = self._load_profiles()
        if not self.profiles:
            print("Warning: No profiles loaded. Using default Chrome profile.")
            self.profiles = self._get_default_profiles()
        
        self.profile_name = profile_name or self._get_supported_profile()
        self.current_profile = self.profiles[self.profile_name]
        
        # Initialize session manager
        self.session_manager = session_manager or SessionManager()
        
        # Initialize session with proxy support
        self.session = self._init_session(proxy)
        
        print(f"Initialized with profile: {self.profile_name}")
        print(f"Available profiles: {', '.join(self.profiles.keys())}")
        if proxy:
            print(f"Using proxy: {proxy}")
    
    def _init_session(self, proxy=None):
        """Initialize a new session with optional proxy"""
        session = requests.Session()
        
        # Load cookies and other session data if available
        session_data = self.session_manager.load_session(self.profile_name)
        if session_data:
            if 'cookies' in session_data:
                for name, value in session_data['cookies'].items():
                    session.cookies.set(name, value)
        
        # Set up proxy if provided
        if proxy:
            session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        return session
    
    def _save_session(self):
        """Save current session state"""
        session_data = {
            'cookies': dict(self.session.cookies),
            'profile': self.profile_name,
            'user_agent': self.current_profile.get('user_agent'),
            'impersonate': self.current_profile.get('impersonate')
        }
        self.session_manager.save_session(self.profile_name, session_data)
        
    def _get_supported_profiles(self):
        """Get list of all supported profile names"""
        return [name for name, profile in self.profiles.items() 
               if profile.get('impersonate') in SUPPORTED_IMPERSONATIONS]
        
    def _get_supported_profile(self):
        """Get a random profile that has a supported impersonation"""
        supported = self._get_supported_profiles()
        if not supported:
            print("Warning: No supported profiles found. Using first available profile.")
            return next(iter(self.profiles.keys()))
        return random.choice(supported)
        
    def _load_profiles(self):
        """Load profiles from JSON file with better error handling"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            profiles_path = os.path.join(current_dir, 'profiles.json')
            
            print(f"Looking for profiles at: {profiles_path}")
            
            if not os.path.exists(profiles_path):
                print(f"Error: profiles.json not found at {profiles_path}")
                return {}
                
            with open(profiles_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
                if content.startswith('\ufeff'):
                    content = content[1:]
                return json.loads(content)
                
        except Exception as e:
            print(f"Error loading profiles: {e}")
            return {}

    def _get_default_profiles(self):
        """Return a default profile if loading fails"""
        return {
            "chrome_default": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "impersonate": "chrome120",
                "headers": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5"
                }
            }
        }

    def rotate_profile(self):
        """Switch to a different supported profile"""
        supported = self._get_supported_profiles()
        if len(supported) <= 1:
            print("Warning: Only one supported profile available, cannot rotate")
            return self.profile_name
            
        # Save current session before rotating
        self._save_session()
            
        # Get all supported profiles except current
        available = [p for p in supported if p != self.profile_name]
        if not available:
            return self.profile_name
            
        # Choose a random profile from available ones
        new_profile = random.choice(available)
        
        # Close current session and initialize new one
        self.profile_name = new_profile
        self.current_profile = self.profiles[self.profile_name]
        self.session = self._init_session(self.session.proxies.get('https') if hasattr(self, 'session') else None)
        
        print(f"\nRotated to profile: {self.profile_name}")
        print(f"User-Agent: {self.current_profile.get('user_agent', 'Not set')}")
        print(f"Impersonating: {self.current_profile.get('impersonate', 'Not set')}")
        return self.profile_name

    def make_request(self, url, method='GET', save_session=True, **kwargs):
        """Make an HTTP request with the current profile"""
        headers = self.current_profile.get('headers', {}).copy()
        if 'headers' in kwargs:
            headers.update(kwargs.pop('headers'))
            
        # Ensure User-Agent is set
        if 'user_agent' in self.current_profile:
            headers['User-Agent'] = self.current_profile['user_agent']
            
        print(f"\nMaking {method} request to {url}")
        print(f"Using profile: {self.profile_name}")
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                verify=False,  # Skip SSL verification for self-signed cert
                impersonate=self.current_profile['impersonate'],
                **kwargs
            )
            
            # Save session after successful request if requested
            if save_session:
                self._save_session()
                
            return response
        except Exception as e:
            print(f"Request failed: {e}")
            return None

def test_rotating_profiles(url, num_requests=10, delay=1, proxy=None):
    """Test profile rotation with multiple requests and session persistence"""
    session_manager = SessionManager()
    client = BrowserClient(session_manager=session_manager, proxy=proxy)
    used_profiles = set()
    
    for i in range(num_requests):
        if i > 0:  # Rotate profile for subsequent requests
            client.rotate_profile()
            
        response = client.make_request(url)
        used_profiles.add(client.profile_name)
            
        if response:
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:200]}...")  # Print first 200 chars
            print(f"Cookies: {dict(response.cookies)}")
            
        if i < num_requests - 1:  # Don't sleep after last request
            time.sleep(delay)
    
    print(f"\nUsed {len(used_profiles)} different profiles: {', '.join(used_profiles)}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test TLS evasion with rotating browser profiles')
    parser.add_argument('--url', default='https://localhost:8443', help='Target URL')
    parser.add_argument('--requests', type=int, default=5, help='Number of requests to make')
    parser.add_argument('--delay', type=float, default=1, help='Delay between requests in seconds')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://user:pass@proxy:port)')
    args = parser.parse_args()
    
    print(f"Testing with rotating profiles against {args.url}")
    if args.proxy:
        print(f"Using proxy: {args.proxy}")
    
    test_rotating_profiles(
        url=args.url,
        num_requests=args.requests,
        delay=args.delay,
        proxy=args.proxy
    )
