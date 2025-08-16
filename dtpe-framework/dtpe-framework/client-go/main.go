package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Profile represents a browser profile with TLS and HTTP settings
type Profile struct {
	Name            string            `json:"name"`
	UserAgent       string            `json:"user_agent"`
	Headers         map[string]string `json:"headers"`
	TLSSettings     *TLSSettings      `json:"tls_settings,omitempty"`
	ScreenResolution string           `json:"screen_resolution,omitempty"`
	Timezone        string            `json:"timezone,omitempty"`
	WebGLVendor     string            `json:"webgl_vendor,omitempty"`
	Platform        string            `json:"platform,omitempty"`
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
	// Create a custom transport with our TLS settings
	transport := &http.Transport{
		TLSHandshakeTimeout: 30 * time.Second,
		// Disable HTTP/2
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		// Set reasonable timeouts
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}

	// Create a new HTTP client with our custom transport
	client := &http.Client{
		Transport: transport,
		// Set a reasonable timeout
		Timeout: 60 * time.Second,
	}

	// Create our browser client
	browserClient := &BrowserClient{
		Client:  client,
		Profile: profile,
	}

	// Apply TLS settings if provided
	if profile.TLSSettings != nil {
		if err := browserClient.SetTLSConfig(); err != nil {
			return nil, fmt.Errorf("failed to set TLS config: %v", err)
		}
	}

	// Set default headers if not provided
	if profile.Headers == nil {
		profile.Headers = make(map[string]string)
	}

	// Ensure User-Agent is set in headers if not already
	if _, ok := profile.Headers["User-Agent"]; !ok && profile.UserAgent != "" {
		profile.Headers["User-Agent"] = profile.UserAgent
	}

	// Add additional headers based on profile
	if profile.Platform != "" {
		profile.Headers["Sec-Ch-Ua-Platform"] = fmt.Sprintf(`"%s"`, profile.Platform)
	}

	// Set default accept headers if not provided
	if _, ok := profile.Headers["Accept"]; !ok {
		profile.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	}

	if _, ok := profile.Headers["Accept-Language"]; !ok {
		profile.Headers["Accept-Language"] = "en-US,en;q=0.9"
	}

	if _, ok := profile.Headers["Accept-Encoding"]; !ok {
		profile.Headers["Accept-Encoding"] = "gzip, deflate, br"
	}

	return browserClient, nil
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

// Do sends an HTTP request and returns an HTTP response
func (c *BrowserClient) Do(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	req = req.Clone(req.Context())

	// Set headers from profile
	for key, value := range c.Profile.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// Ensure User-Agent is set
	if req.Header.Get("User-Agent") == "" && c.Profile.UserAgent != "" {
		req.Header.Set("User-Agent", c.Profile.UserAgent)
	}

	// Add additional headers based on profile
	if c.Profile.Platform != "" && req.Header.Get("Sec-Ch-Ua-Platform") == "" {
		req.Header.Set("Sec-Ch-Ua-Platform", fmt.Sprintf(`"%s"`, c.Profile.Platform))
	}

	// Add screen resolution if available
	if c.Profile.ScreenResolution != "" && req.Header.Get("X-Screen-Resolution") == "" {
		req.Header.Set("X-Screen-Resolution", c.Profile.ScreenResolution)
	}

	// Force HTTP/1.1
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	// Log request details for debugging
	log.Printf("Sending %s request to %s with headers: %+v", req.Method, req.URL, req.Header)

	// Execute the request
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	return resp, nil
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

// ProfileManager manages browser profiles and rotation
type ProfileManager struct {
	profiles    map[string]*Profile
	profileKeys []string
	currentIdx  int
	mu          sync.Mutex
}

// NewProfileManager creates a new ProfileManager with the given profiles
func NewProfileManager(profiles []*Profile) *ProfileManager {
	pm := &ProfileManager{
		profiles:    make(map[string]*Profile),
		profileKeys: make([]string, 0, len(profiles)),
		currentIdx:  0,
	}

	for _, profile := range profiles {
		pm.profiles[profile.Name] = profile
		pm.profileKeys = append(pm.profileKeys, profile.Name)
	}

	// Shuffle the profile keys for random rotation
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(pm.profileKeys), func(i, j int) {
		pm.profileKeys[i], pm.profileKeys[j] = pm.profileKeys[j], pm.profileKeys[i]
	})

	return pm
}

// GetProfile returns a profile by name
func (pm *ProfileManager) GetProfile(name string) (*Profile, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	profile, exists := pm.profiles[name]
	return profile, exists
}

// GetNextProfile returns the next profile in rotation
func (pm *ProfileManager) GetNextProfile() *Profile {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.profileKeys) == 0 {
		return nil
	}

	// Get the current profile
	profileName := pm.profileKeys[pm.currentIdx]
	profile := pm.profiles[profileName]

	// Move to the next profile
	pm.currentIdx = (pm.currentIdx + 1) % len(pm.profileKeys)

	// If we've gone through all profiles, reshuffle for next time
	if pm.currentIdx == 0 {
		rand.Shuffle(len(pm.profileKeys), func(i, j int) {
			pm.profileKeys[i], pm.profileKeys[j] = pm.profileKeys[j], pm.profileKeys[i]
		})
	}

	return profile
}

// GetRandomProfile returns a random profile
func (pm *ProfileManager) GetRandomProfile() *Profile {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.profileKeys) == 0 {
		return nil
	}

	idx := rand.Intn(len(pm.profileKeys))
	return pm.profiles[pm.profileKeys[idx]]
}

// GetProfiles returns all available profiles
func (pm *ProfileManager) GetProfiles() []*Profile {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	profiles := make([]*Profile, 0, len(pm.profiles))
	for _, name := range pm.profileKeys {
		profiles = append(profiles, pm.profiles[name])
	}
	return profiles
}

// LoadProfiles loads browser profiles from a JSON file
func LoadProfiles(filename string) (*ProfileManager, error) {
	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles file: %v", err)
	}

	// Parse the JSON data into a map
	var profilesMap map[string]*Profile
	if err := json.Unmarshal(data, &profilesMap); err != nil {
		return nil, fmt.Errorf("failed to parse profiles: %v", err)
	}

	// Convert the map to a slice
	profiles := make([]*Profile, 0, len(profilesMap))
	for name, profile := range profilesMap {
		// Ensure the name is set
		profile.Name = name
		profiles = append(profiles, profile)
	}

	// Create a new profile manager
	return NewProfileManager(profiles), nil
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
	// Load profiles from file
	profileManager, err := LoadProfiles("profiles.json")
	if err != nil {
		log.Fatalf("Failed to load profiles: %v", err)
	}

	// Get all available profiles
	profiles := profileManager.GetProfiles()
	if len(profiles) == 0 {
		log.Fatal("No profiles found")
	}

	// Display available profiles
	log.Println("Available profiles:")
	for i, p := range profiles {
		log.Printf("%d. %s (%s)", i+1, p.Name, p.UserAgent)
	}
	log.Println()

	// Test with each profile sequentially
	log.Println("=== Testing with each profile sequentially ===")
	for _, profile := range profiles {
		testWithProfile(profile, "https://httpbin.org/headers")
		time.Sleep(2 * time.Second) // Add delay between profile tests
	}

	// Test with profile rotation
	log.Println("\n=== Testing with profile rotation ===")
	for i := 0; i < 3; i++ {
		profile := profileManager.GetNextProfile()
		log.Printf("\n--- Using profile: %s (rotation %d) ---", profile.Name, i+1)
		testWithProfile(profile, "https://httpbin.org/headers")
		time.Sleep(2 * time.Second)
	}

	// Test with random profile selection
	log.Println("\n=== Testing with random profile selection ===")
	for i := 0; i < 3; i++ {
		profile := profileManager.GetRandomProfile()
		log.Printf("\n--- Using random profile: %s (attempt %d) ---", profile.Name, i+1)
		testWithProfile(profile, "https://httpbin.org/headers")
		time.Sleep(2 * time.Second)
	}
}

// testWithProfile creates a client with the given profile and tests it
func testWithProfile(profile *Profile, url string) {
	log.Printf("Testing with profile: %s", profile.Name)
	log.Printf("User-Agent: %s", profile.UserAgent)

	// Create a new browser client
	client, err := NewBrowserClient(profile)
	if err != nil {
		log.Printf("Failed to create browser client: %v", err)
		return
	}

	// Test the client with the specified URL
	testRequest(client, url)
}
