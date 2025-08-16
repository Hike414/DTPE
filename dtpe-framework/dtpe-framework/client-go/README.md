# DTPE Go Client

A Go implementation of the Dynamic TLS Parameter Evasion client using uTLS for advanced TLS fingerprinting.

## Features

- Customizable TLS configurations
- Support for multiple browser profiles
- uTLS integration for realistic TLS fingerprints
- Easy-to-use API
- Profile-based configuration

## Prerequisites

- Go 1.20 or later
- Git

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Hike414/dtp-framework.git
   cd dtp-framework/client-go
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

## Usage

### Basic Usage

```bash
# Run with default Chrome profile
go run main.go
```

### Using a Specific Profile

```bash
# Run with a specific profile from profiles.json
go run main.go -profile chrome_windows
```

### Command Line Arguments

- `-profile`: Specify a browser profile to use (default: chrome_windows)
- `-url`: Target URL (default: https://tls.peet.ws/api/all)
- `-insecure`: Skip TLS certificate verification (default: false)

## Profiles

Profiles are defined in `profiles.json` and include:
- Browser name and version
- User-Agent string
- Default HTTP headers
- TLS configuration (cipher suites, curves, etc.)

## Building

To build the client:

```bash
go build -o dtpe-client
```

## Testing

To test the client against the local TLS server:

```bash
# Start the local server (from the server directory)
cd ../server
go run main.go

# In another terminal, run the client
cd ../client-go
go run main.go -url https://localhost:8443
```

## License

MIT
