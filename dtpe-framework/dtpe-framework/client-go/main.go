package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Profile represents a browser profile with TLS and HTTP settings
type Profile struct {
	Name        string            `json:"name"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	TLSSettings *TLSSettings      `json:"tls_settings,omitempty"`
}

// TLSSettings defines the TLS configuration for a profile
type TLSSettings struct {
	MinVersion            uint16         `json:"min_version"`
	MaxVersion            uint16         `json:"max_version"`
	CipherSuites          []uint16       `json:"cipher_suites"`
	CurvePreferences      []utls.CurveID `json:"curve_preferences"`
	SessionTicketsDisabled bool           `json:"session_tickets_disabled"`
}

// BrowserClient represents a client that can make HTTP requests with a specific profile
type BrowserClient struct {
	Client  *http.Client
	Profile *Profile
	tlsConfig *utls.Config
}

// customTransport implements http.RoundTripper that uses uTLS for the TLS handshake
type customTransport struct {
	tlsConfig *utls.Config
	profile   *Profile
	debug     bool // Enable debug logging
}

// dialTLSWithUTLS performs the TLS handshake using uTLS but returns a standard tls.Conn
type dialTLSWithUTLS struct {
	tlsConfig *utls.Config
}

// Dial creates a new TLS connection using uTLS
func (d *dialTLSWithUTLS) Dial(network, addr string) (net.Conn, error) {
	// Parse the host and port from the address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %v", err)
	}

	// Create a TCP connection
	conn, err := net.DialTimeout(network, addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %v", addr, err)
	}

	// Create a new uTLS connection
	configCopy := d.tlsConfig.Clone()
	configCopy.ServerName = host

	uTLSConn := utls.UClient(conn, configCopy, utls.HelloChrome_Auto)

	// Perform TLS handshake
	if err := uTLSConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %v", err)
	}

	// Return the underlying connection which implements net.Conn
	return uTLSConn.Conn, nil
}

// RoundTrip executes a single HTTP transaction, returning a Response for the provided Request.
func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.debug {
		log.Printf("Starting RoundTrip for %s %s", req.Method, req.URL.String())
	}

	// Create a custom transport that uses our uTLS dialer
	transport := &http.Transport{
		// Use our custom dialer that performs the TLS handshake with uTLS
		DialTLS: (&dialTLSWithUTLS{
			tlsConfig: t.tlsConfig,
		}).Dial,
		// Force HTTP/1.1
		ForceAttemptHTTP2: false,
		// Set reasonable timeouts
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		// Disable keep-alive to simplify debugging
		DisableKeepAlives: true,
	}

	// Create a one-time client with our custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Clone the request to avoid modifying the original
	req = req.Clone(context.Background())

	// Set the User-Agent header if not already set
	if req.Header.Get("User-Agent") == "" && t.profile.UserAgent != "" {
		req.Header.Set("User-Agent", t.profile.UserAgent)
	}

	// Add additional headers from profile
	for key, value := range t.profile.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// Make the request
	return client.Do(req)
}

// NewBrowserClient creates a new BrowserClient with the given profile
func NewBrowserClient(profile *Profile) (*BrowserClient, error) {
	client := &BrowserClient{
		Profile: profile,
	}

	// Set up TLS configuration
	if err := client.SetTLSConfig(); err != nil {
		return nil, fmt.Errorf("failed to set TLS config: %v", err)
	}

	// Create HTTP client with custom transport
	client.Client = &http.Client{
		Transport: &customTransport{
			tlsConfig: client.tlsConfig,
			profile:   profile,
			debug:     true, // Enable debug logging
		},
		Timeout: 30 * time.Second,
		// Disable automatic redirects to handle them manually
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

// SetTLSConfig applies TLS settings from the profile
func (c *BrowserClient) SetTLSConfig() error {
	// Initialize TLS config with default values
	c.tlsConfig = &utls.Config{
		InsecureSkipVerify: true, // Skip cert verification for testing
		ServerName:         "example.com", // Will be overridden per-request
		NextProtos:         []string{"http/1.1"}, // Only HTTP/1.1 for now
	}

	// Apply profile-specific TLS settings if available
	if c.Profile.TLSSettings != nil {
		settings := c.Profile.TLSSettings
		c.tlsConfig.MinVersion = settings.MinVersion
		c.tlsConfig.MaxVersion = settings.MaxVersion
		c.tlsConfig.CipherSuites = settings.CipherSuites
		c.tlsConfig.CurvePreferences = settings.CurvePreferences
		c.tlsConfig.SessionTicketsDisabled = settings.SessionTicketsDisabled
	}

	return nil
}

// Helper function to convert TLS version numbers to strings
func versionToString(version uint16) string {
	switch version {
	case utls.VersionTLS10:
		return "TLS 1.0"
	case utls.VersionTLS11:
		return "TLS 1.1"
	case utls.VersionTLS12:
		return "TLS 1.2"
	case utls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

// Do sends an HTTP request and returns an HTTP response
func (c *BrowserClient) Do(req *http.Request) (*http.Response, error) {
	// Log request details
	log.Printf("Sending %s request to %s", req.Method, req.URL.String())
	log.Printf("Headers: %+v", req.Header)

	// Make the request using the custom transport
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}

	// Log response details
	log.Printf("Received %d %s from %s", resp.StatusCode, resp.Proto, req.URL.Host)
	log.Printf("Response headers: %+v", resp.Header)

	return resp, nil
}

// LoadProfiles loads browser profiles from a JSON file
func LoadProfiles(filename string) ([]*Profile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading profiles file: %v", err)
	}

	var profiles []*Profile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("error parsing profiles: %v", err)
	}

	return profiles, nil
}

// ChromeProfile returns a Chrome browser profile
func ChromeProfile() *Profile {
	return &Profile{
		Name:      "chrome_windows",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
		},
		TLSSettings: &TLSSettings{
			MinVersion: utls.VersionTLS12,
			MaxVersion: utls.VersionTLS13,
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			CurvePreferences: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			},
			SessionTicketsDisabled: false,
		},
	}
}

func testRequest(client *BrowserClient, url string) {
	log.Printf("\n=== Testing request to %s ===", url)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	// Set minimal headers
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", client.Profile.UserAgent)

	// Log request details
	log.Printf("Sending request to %s", url)
	log.Printf("Headers: %+v", req.Header)

	// Make the request with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req = req.WithContext(ctx)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("Request failed after %v: %v", elapsed, err)
		return
	}
	defer resp.Body.Close()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return
	}

	// Print response details
	log.Printf("Response received in %v:", elapsed)
	log.Printf("Status: %s", resp.Status)
	log.Printf("Headers: %+v", resp.Header)
	log.Printf("Body (first 500 bytes): %s\n", safeSubstring(body).Substring(0, 500))
}

// safeSubstring returns a substring of s from start to end, handling out of bounds
type safeSubstring string

func (s safeSubstring) Substring(start, end int) string {
	runes := []rune(string(s))
	if start < 0 {
		start = 0
	}
	if end > len(runes) {
		end = len(runes)
	}
	if start > end {
		return ""
	}
	return string(runes[start:end])
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("Starting DTPE Go client...")

	// Example usage
	profile := ChromeProfile()
	log.Printf("Created profile: %s", profile.Name)

	client, err := NewBrowserClient(profile)
	if err != nil {
		log.Fatalf("Failed to create browser client: %v", err)
	}

	// Test with different endpoints
	testEndpoints := []string{
		"https://httpbin.org/headers",
		"https://httpbin.org/ip",
		"https://httpbin.org/user-agent",
	}

	for _, endpoint := range testEndpoints {
		testRequest(client, endpoint)
	}

	log.Println("All tests completed.")
}
