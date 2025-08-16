# Dynamic TLS Parameter Evasion (DTPE) Framework

A comprehensive framework for testing and evading TLS fingerprinting through dynamic parameter manipulation.

## Features

- **Multi-browser Support**: Emulate Chrome, Firefox, Safari, and Edge
- **Platform Coverage**: Windows, macOS, iOS, and Android profiles
- **Advanced Evasion**: JA3 fingerprint randomization and TLS parameter manipulation
- **Dual Implementation**: Available in both Python and Go

## Quick Start

### Prerequisites
- Go 1.20+ (for Go client)
- Python 3.8+ (for Python client)
- Git

### Running the Project

1. **Start the Adversarial Server**:
   ```bash
   cd server
   go run server.go
   ```

2. **Run the Go Client**:
   ```powershell
   .\start-go.ps1  # Windows
   # OR
   cd client-go && go run main.go  # Any platform
   ```

3. **Run the Python Client**:
   ```bash
   cd client-python
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   # OR
   source venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   python client.py
   ```

## Project Structure

```
dtpe-framework/
├── client-go/           # Go implementation using uTLS
│   ├── main.go
│   ├── profiles.json
│   └── go.mod
├── client-python/       # Python implementation using curl_cffi
│   ├── client.py
│   ├── profiles.json
│   └── requirements.txt
└── server/              # Adversarial test server
    ├── server.go
    ├── server.key
    └── server.pem
```

## Browser Profiles

Pre-configured profiles include:
- Chrome (Windows, macOS, Android)
- Firefox (Windows, macOS)
- Safari (macOS, iOS)
- Edge (Windows)

## Advanced Usage

### Custom Profiles
Edit the `profiles.json` file to add or modify browser profiles:

```json
{
  "chrome_windows": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "tls": {
      "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
      "extensions": ["server_name", "extended_master_secret"]
    },
    "headers": {
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5"
    }
  }
}
```

### Proxy Configuration
Set environment variables for proxy support:

```bash
# HTTP/HTTPS proxy
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# SOCKS5 proxy
export ALL_PROXY=socks5://proxy.example.com:1080
```

## Troubleshooting

### Common Issues

1. **Certificate Errors**:
   - Ensure server certificates are trusted
   - Use `-insecure` flag for testing (not recommended for production)

2. **TLS Handshake Failures**:
   - Verify cipher suite compatibility
   - Check TLS version support

3. **Proxy Connection Issues**:
   - Verify proxy settings
   - Check firewall rules

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [uTLS](https://github.com/refraction-networking/utls) - TLS fingerprinting evasion
- [curl_cffi](https://github.com/yifeikong/curl_cffi) - Python bindings for curl-impersonate
