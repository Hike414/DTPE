package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// ja3er calculates the JA3 string from a ClientHelloInfo object
func ja3er(hello *tls.ClientHelloInfo) (string, string) {
	// 1. TLS Version
	version := strconv.Itoa(int(hello.SupportedVersions[0]))

	// 2. Cipher Suites
	var ciphers []string
	for _, cipher := range hello.CipherSuites {
		ciphers = append(ciphers, strconv.Itoa(int(cipher)))
	}

	// 3. Extensions (empty in this implementation)
	extensions := ""

	// 4. Elliptic Curves
	var curves []string
	for _, curve := range hello.SupportedCurves {
		curves = append(curves, strconv.Itoa(int(curve)))
	}

	// 5. Elliptic Curve Point Formats
	var formats []string
	for _, pointFormat := range hello.SupportedPoints {
		formats = append(formats, strconv.Itoa(int(pointFormat)))
	}

	// Combine all parts
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		extensions,
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	)

	// Calculate MD5 hash
	hash := md5.Sum([]byte(ja3String))
	ja3Hash := hex.EncodeToString(hash[:])

	return ja3String, ja3Hash
}

func main() {
    // Load the certificate and key
    cert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
    if err != nil {
        log.Fatalf("Failed to load certificate: %v", err)
    }

    // Configure the TLS server
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
            ja3String, ja3Hash := ja3er(hello)
            log.Println("--- New Client Connection ---")
            log.Printf("Remote Addr: %s", hello.Conn.RemoteAddr())
            log.Printf("Server Name: %s", hello.ServerName)
            log.Printf("JA3 String:  %s", ja3String)
            log.Printf("JA3 Hash:    %s", ja3Hash)
            log.Println("-----------------------------")
            return nil, nil
        },
    }

    // Define HTTP handler
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        log.Println("--- HTTP Request Received ---")
        log.Printf("User-Agent: %s", r.Header.Get("User-Agent"))
        
        // Log header order
        var headerOrder []string
        for k := range r.Header {
            headerOrder = append(headerOrder, k)
        }
        log.Printf("Header Order: %s", strings.Join(headerOrder, ", "))
        fmt.Fprintf(w, "Hello! Your TLS fingerprint has been logged.")
        log.Println("---------------------------")
    })

    // Create and start the server
    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    log.Println("Starting adversarial TLS server on https://localhost:8443")
    log.Fatal(server.ListenAndServeTLS("", ""))
}