package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
)

type appConfig struct {
	Domains     []string
	Email       string
	Upstream    *url.URL
	HTTPPort    string
	HTTPSPort   string
	StoragePath string
	ACMEDir     string
	LocalCert   string
	LocalKey    string
	DisableTLS  bool
}

func main() {
	logger := log.New(os.Stdout, "[certmagic-proxy] ", log.LstdFlags|log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("configuration error: %v", err)
	}

	logger.Printf("starting proxy upstream=%s", cfg.Upstream)

	proxy := newReverseProxy(cfg.Upstream, logger)
	loggingHandler := loggingMiddleware(logger, cfg.Upstream, proxy)

	if cfg.DisableTLS {
		logger.Printf("TLS disabled; listening on http :%s only", cfg.HTTPPort)
		httpServer := &http.Server{
			Addr:    ":" + cfg.HTTPPort,
			Handler: loggingHandler,
		}
		runServers(logger, httpServer, nil)
		return
	}

	if cfg.LocalCert != "" && cfg.LocalKey != "" {
		logger.Printf("using static certificate cert=%s key=%s", cfg.LocalCert, cfg.LocalKey)
		keypair, err := tls.LoadX509KeyPair(cfg.LocalCert, cfg.LocalKey)
		if err != nil {
			logger.Fatalf("loading tls keypair failed: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS12,
		}

		httpServer := &http.Server{
			Addr:    ":" + cfg.HTTPPort,
			Handler: httpRedirectHandler(cfg.HTTPSPort),
		}
		httpsServer := &http.Server{
			Addr:      ":" + cfg.HTTPSPort,
			Handler:   loggingHandler,
			TLSConfig: tlsConfig,
		}
		runServers(logger, httpServer, httpsServer)
		return
	}

	logger.Printf("certmagic enabled for domains=%v storage=%s", cfg.Domains, cfg.StoragePath)

	if err := initCertmagic(cfg, logger); err != nil {
		logger.Fatalf("certmagic init failed: %v", err)
	}

	magic := certmagic.NewDefault()
	magic.Storage = &certmagic.FileStorage{Path: cfg.StoragePath}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := magic.ManageSync(ctx, cfg.Domains); err != nil {
		logger.Fatalf("certificate provisioning failed: %v", err)
	}

	httpServer := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: certmagic.DefaultACME.HTTPChallengeHandler(httpRedirectHandler(cfg.HTTPSPort)),
	}

	httpsServer := &http.Server{
		Addr:      ":" + cfg.HTTPSPort,
		Handler:   loggingHandler,
		TLSConfig: magic.TLSConfig(),
	}

	runServers(logger, httpServer, httpsServer)
}

func loadConfig() (*appConfig, error) {
	upstreamRaw := strings.TrimSpace(os.Getenv("UPSTREAM_URL"))
	if upstreamRaw == "" {
		return nil, fmt.Errorf("UPSTREAM_URL is required")
	}

	upstreamURL, err := url.Parse(upstreamRaw)
	if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return nil, fmt.Errorf("UPSTREAM_URL must be a valid absolute URL: %w", err)
	}

	httpPort := envOrDefault("HTTP_PORT", "80")
	httpsPort := envOrDefault("HTTPS_PORT", "443")
	storagePath := envOrDefault("CERTMAGIC_STORAGE", "certmagic-cache")

	localCert := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	localKey := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	disableTLS := envBool("DISABLE_TLS")

	domainEnv := os.Getenv("CERTMAGIC_DOMAINS")
	rawDomains := strings.Split(domainEnv, ",")
	domains := make([]string, 0, len(rawDomains))
	for _, d := range rawDomains {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			domains = append(domains, trimmed)
		}
	}

	useStaticCert := localCert != "" || localKey != ""
	if useStaticCert && (localCert == "" || localKey == "") {
		return nil, fmt.Errorf("both TLS_CERT_FILE and TLS_KEY_FILE are required when supplying one")
	}

	if !disableTLS && !useStaticCert && len(domains) == 0 {
		return nil, fmt.Errorf("CERTMAGIC_DOMAINS is required (comma-separated) unless TLS is disabled or a static cert is provided")
	}

	cfg := &appConfig{
		Domains:     domains,
		Email:       strings.TrimSpace(os.Getenv("CERTMAGIC_EMAIL")),
		Upstream:    upstreamURL,
		HTTPPort:    httpPort,
		HTTPSPort:   httpsPort,
		StoragePath: storagePath,
		ACMEDir:     strings.TrimSpace(os.Getenv("ACME_DIRECTORY")),
		LocalCert:   localCert,
		LocalKey:    localKey,
		DisableTLS:  disableTLS,
	}

	return cfg, nil
}

func initCertmagic(cfg *appConfig, logger *log.Logger) error {
	if cfg.Email != "" {
		certmagic.DefaultACME.Email = cfg.Email
	}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = false
	certmagic.DefaultACME.DisableTLSALPNChallenge = false

	if cfg.ACMEDir != "" {
		logger.Printf("using custom ACME directory %s", cfg.ACMEDir)
		certmagic.DefaultACME.CA = cfg.ACMEDir
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.StoragePath}

	return nil
}

func newReverseProxy(target *url.URL, logger *log.Logger) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		baseDirector(req)
		req.Host = target.Host

		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Uri", req.URL.RequestURI())
		req.Header.Set("X-Forwarded-For", appendForwardedFor(req.Header.Get("X-Forwarded-For"), req.RemoteAddr))
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Printf("proxy error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
	}

	proxy.FlushInterval = 100 * time.Millisecond

	return proxy
}

func loggingMiddleware(logger *log.Logger, upstream *url.URL, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newResponseRecorder(w)
		start := time.Now()

		next.ServeHTTP(rec, r)

		duration := time.Since(start)
		remoteIP := clientIP(r.RemoteAddr)
		tlsInfo, fingerprint := tlsSummary(r.TLS)

		logger.Printf(
			`forwarded method=%s status=%d host=%s uri=%s upstream=%s bytes=%d remote=%s tls=%s fingerprint=%s took=%s`,
			r.Method,
			rec.status,
			r.Host,
			r.URL.RequestURI(),
			upstream.String(),
			rec.bytes,
			remoteIP,
			tlsInfo,
			fingerprint,
			duration.Round(time.Millisecond),
		)
	})
}

func httpRedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpsPort == "" {
			http.Error(w, "https disabled", http.StatusServiceUnavailable)
			return
		}

		targetHost := r.Host
		if hostOnly, _, err := net.SplitHostPort(r.Host); err == nil {
			targetHost = hostOnly
		}

		if httpsPort != "443" {
			targetHost = net.JoinHostPort(targetHost, httpsPort)
		}

		target := "https://" + targetHost + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func tlsSummary(state *tls.ConnectionState) (string, string) {
	if state == nil {
		return "plaintext", "absent"
	}

	version := tlsVersion(state.Version)
	cipher := tlsCipher(state.CipherSuite)

	fingerprint := computeTLSFingerprint(state)

	return fmt.Sprintf("%s/%s", version, cipher), fingerprint
}

func computeTLSFingerprint(state *tls.ConnectionState) string {
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%d", state.Version)))
	hasher.Write([]byte(fmt.Sprintf("%d", state.CipherSuite)))
	hasher.Write([]byte(state.NegotiatedProtocol))
	hasher.Write([]byte(state.ServerName))
	if state.TLSUnique != nil {
		hasher.Write(state.TLSUnique)
	}

	for _, cert := range state.PeerCertificates {
		hasher.Write(cert.Raw)
	}

	sum := hasher.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func tlsCipher(cipher uint16) string {
	switch cipher {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_ECDSA_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_RSA_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_ECDSA_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_ECDSA_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_RSA_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("0x%x", cipher)
	}
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func appendForwardedFor(existing, remoteAddr string) string {
	ip := clientIP(remoteAddr)
	if existing == "" {
		return ip
	}
	return existing + ", " + ip
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func envOrDefault(key, fallback string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}

func envBool(key string) bool {
	val := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch val {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func runServers(logger *log.Logger, httpServer, httpsServer *http.Server) {
	errCh := make(chan error, 2)

	if httpServer != nil {
		go func() {
			logger.Printf("http listener ready on %s", httpServer.Addr)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http server: %w", err)
			}
		}()
	}

	if httpsServer != nil {
		go func() {
			logger.Printf("https listener ready on %s", httpsServer.Addr)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("https server: %w", err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Printf("received signal %s, shutting down...", sig)
	case err := <-errCh:
		logger.Printf("server error: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if httpServer != nil {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("http shutdown error: %v", err)
		}
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("https shutdown error: %v", err)
		}
	}

	logger.Println("shutdown complete")
}
