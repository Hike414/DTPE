from curl_cffi import requests

def test_server():
    url = "https://localhost:8443"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    try:
        print(f"Connecting to {url}...")
        # Using 'chrome124' as the impersonation profile
        response = requests.get(
            url, 
            headers=headers, 
            verify=False,  # Skip SSL verification for self-signed cert
            impersonate="chrome124"  # This sets Chrome-like TLS fingerprint
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        print("Check the server logs to see the JA3 fingerprint")
        
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    test_server()
