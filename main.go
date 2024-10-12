package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/bosley/lighthouse/ds"
)

var ServerConfig ConfigInfo

func main() {
	// Define command-line flags
	newFlag := flag.Bool("new", false, "Create a new configuration")
	sslDir := flag.String("ssl", "", "Directory for SSL certificate and key generation")
	dbPath := flag.String("db", "", "Path to the database file")
	certPath := flag.String("cert", "", "Path to the SSL certificate")
	keyPath := flag.String("key", "", "Path to the SSL key")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	portInfo := flag.String("port", ":8089", "Port to use")

	flag.Parse()

	setupLogger(*debugFlag)
	slog.Debug("Starting main function", "debug", *debugFlag)

	// Check flag combinations and perform actions
	if *newFlag {
		if err := handleNewFlag(*sslDir, *dbPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := handleExistingConfig(*certPath, *keyPath, *dbPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	ServerConfig.Port = *portInfo

	// Attempt to load LIGHTHOUSE_SECRET_KEY from environment
	secretKey := os.Getenv("LIGHTHOUSE_SECRET_KEY")
	if secretKey == "" {
		slog.Error("LIGHTHOUSE_SECRET_KEY environment variable is not set")
		fmt.Fprintf(os.Stderr, "Error: LIGHTHOUSE_SECRET_KEY environment variable is required for JWT operations\n")
		os.Exit(1)
	}

	// Store the secret key in ServerConfig
	ServerConfig.SKey = []byte(secretKey)

	slog.Debug("Successfully loaded LIGHTHOUSE_SECRET_KEY")

	// If we've reached this point, all checks have passed
	fmt.Println("Application setup successful")

	// Ensure ServerConfig doesn't have null members
	if ServerConfig.DB == nil {
		fmt.Fprintf(os.Stderr, "Error: Database configuration is missing\n")
		os.Exit(1)
	}
	if ServerConfig.TLSConfig == nil {
		fmt.Fprintf(os.Stderr, "Error: TLS configuration is missing\n")
		os.Exit(1)
	}

	Serve()
}

func setupLogger(debug bool) {
	var logLevel slog.Level
	if debug {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			if len(groups) == 0 {
				a.Value = slog.StringValue(fmt.Sprintf("\x1b[36m%s\x1b[0m", a.Key))
			}
			return a
		},
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func handleNewFlag(sslDir, dbPath string) error {
	slog.Debug("Handling new flag", "sslDir", sslDir, "dbPath", dbPath)
	if sslDir != "" && dbPath != "" {
		return fmt.Errorf("--ssl and --db cannot be used together")
	}

	if sslDir == "" && dbPath == "" {
		return fmt.Errorf("either --ssl or --db must be provided with --new")
	}

	if sslDir != "" {
		return generateSSLCertAndKey(sslDir)
	}

	_, err := ds.SetupNewDatabase(dbPath)
	return err
}

func handleExistingConfig(certPath, keyPath, dbPath string) error {
	slog.Debug("Handling existing config", "certPath", certPath, "keyPath", keyPath, "dbPath", dbPath)
	if certPath == "" || keyPath == "" || dbPath == "" {
		return fmt.Errorf("--cert, --key, and --db are required when --new is not present")
	}

	tlsConfig, err := validateTLSConfig(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}

	db, err := ds.LoadExistingDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to load existing database: %w", err)
	}

	ServerConfig = ConfigInfo{
		DB:        db,
		TLSConfig: tlsConfig,
	}

	return nil
}

func generateSSLCertAndKey(sslDir string) error {
	slog.Debug("Generating SSL certificate and key", "sslDir", sslDir)
	// Check if directory exists
	if _, err := os.Stat(sslDir); os.IsNotExist(err) {
		return fmt.Errorf("SSL directory does not exist: %s", sslDir)
	}

	certPath := filepath.Join(sslDir, "server.crt")
	keyPath := filepath.Join(sslDir, "server.key")

	// Check if files already exist
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("certificate file already exists: %s", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("key file already exists: %s", keyPath)
	}

	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Lighthouse Self-Signed Certificate"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("0.0.0.0"),
			net.IPv6loopback,
			net.IPv6unspecified,
		},
		DNSNames: []string{"localhost"},
	}

	// Create the self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write the private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	fmt.Println("Self-signed certificate and key generated successfully")
	return nil
}

func validateTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	slog.Debug("Validating TLS config", "certPath", certPath, "keyPath", keyPath)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
