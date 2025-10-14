package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
)

const (
	DefaultBootstrapResolver    = "9.9.9.9:53"
	DefaultKeepAlive            = 5 * time.Second
	DefaultTimeout              = 30 * time.Second
	ResolverReadTimeout         = 5 * time.Second
	SystemResolverIPTTL         = 12 * time.Hour
	MinResolverIPTTL            = 4 * time.Hour
	ResolverIPTTLMaxJitter      = 15 * time.Minute
	ExpiredCachedIPGraceTTL     = 15 * time.Minute
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second
)

// Some variables
var rebuildingTransport bool = false
var hasTLSConnected int = 0
var preferIPv6 = false

type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

type AltSupport struct {
	sync.RWMutex
	cache map[string]uint16
}

type XTransport struct {
	UserAgent                string
	DisableKeepAlives        bool
	RetryWith2               bool
	transport                *http.Transport
	h3Transport              *http3.Transport
	keepAlive                time.Duration
	timeout                  time.Duration
	InsecureSkipVerify       bool
	cachedIPs                CachedIPs
	altSupport               AltSupport
	internalResolvers        []string
	bootstrapResolvers       []string
	mainProto                string
	NoFallback               bool
	ignoreSystemDNS          bool
	internalResolverReady    bool
	useIPv4                  bool
	useIPv6                  bool
	http3                    bool
	http3Probe               bool
	MaxVersion               uint16
	tlsDisableSessionTickets bool
	tlsCipherSuite           []uint16
	DropTLS13                bool
	DropTLS12                bool
	keepCipherSuite          bool
	CSHandleError            int
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
	tlsClientCreds           DOHClientCreds
	keyLogWriter             io.Writer
}

func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse")
	}
	xTransport := XTransport{
		UserAgent:                DefaultUserAgent,
		DisableKeepAlives:        true,
		RetryWith2:               true,
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:               AltSupport{cache: make(map[string]uint16)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		InsecureSkipVerify:       false,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		mainProto:                "",
		NoFallback:               true,
		ignoreSystemDNS:          true,
		useIPv4:                  true,
		useIPv6:                  false,
		http3:                    false,
		http3Probe:               false,
		tlsDisableSessionTickets: true,
		tlsCipherSuite:           nil,
		keepCipherSuite:          false,
		CSHandleError:            0,
		keyLogWriter:             nil,
	}
	return &xTransport
}

// Trim the IP String
func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	unique := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copyIP := append(net.IP(nil), ip...)
		key := copyIP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, copyIP)
	}
	return unique
}

func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}
	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}
	xTransport.cachedIPs.Lock()
	item.updatingUntil = nil
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()
	if len(normalized) == 1 {
		dlog.Infof("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Infof("[%s] cached %d IP addresses (first: %s), valid for %v", host, len(normalized), normalized[0], ttl)
	}
}

func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	xTransport.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// Mark an entry as being updated
func (xTransport *XTransport) markUpdatingCachedIP(host string) {
	xTransport.cachedIPs.Lock()
	item, ok := xTransport.cachedIPs.cache[host]
	if ok {
		now := time.Now()
		until := now.Add(xTransport.timeout)
		item.updatingUntil = &until
		xTransport.cachedIPs.cache[host] = item
	}
	item = nil
	xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	ips = nil
	xTransport.cachedIPs.RLock()
	item, ok := xTransport.cachedIPs.cache[host]
	if !ok {
		xTransport.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}
	if len(item.ips) > 0 {
		ips = make([]net.IP, 0, len(item.ips))
		for _, ip := range item.ips {
			if ip == nil {
				continue
			}
			ips = append(ips, append(net.IP(nil), ip...))
		}
	}
	expiration := item.expiration
	updatingUntil := item.updatingUntil
	xTransport.cachedIPs.RUnlock()
	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IP addresses are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
		}
	}
	return ips, expired, updating
}

func (xTransport *XTransport) loadCachedIP(host string) (ip net.IP, expired bool, updating bool) {
	ips, expired, updating := xTransport.loadCachedIPs(host)
	if len(ips) > 0 {
		return ips[0], expired, updating
	}
	return nil, expired, updating
}

// DefaultTLSCipherSuites The default TLS 1.2 secure cipher suites
func DefaultTLSCipherSuites() []uint16 {
	return []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
}

// Rebuild the transport. This will maybe drop the connection protocol or cipher
func (xTransport *XTransport) rebuildTransport() {
	if rebuildingTransport {
		dlog.Notice(" [ ! ] Transport: Rebuild already in progress.")
		return
	}
	rebuildingTransport = true
	defer func() {
		rebuildingTransport = false
		xTransport.transport.CloseIdleConnections()
		dlog.Info(" [ + ] Transport: Rebuilding complete.")
	}()
	dlog.Info(" [ + ] Transport: Started rebuilding.")
	if xTransport.transport != nil {
		dlog.Info(" [ ! ] Transport: Closing idle connections.")
		xTransport.transport.CloseIdleConnections()
	}
	timeout := xTransport.timeout

	clientCreds := xTransport.tlsClientCreds
	certPool, certPoolErr := x509.SystemCertPool()
	xCert := tls.Certificate{}
	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		additionalCaCert, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", clientCreds.rootCA, err)
		}
		if additionalCaCert == nil {
			dlog.Fatal("Additional CA certificate not supported on this platform.")
		} else {
			if err == nil {
				if ok := certPool.AppendCertsFromPEM(additionalCaCert); !ok {
					dlog.Fatalf("No valid certificates found in rootCA file [%s]", clientCreds.rootCA)
				}
			}
		}
	}

	if certPool != nil {
		// Some operating systems don't include Let's Encrypt ISRG Root X1 certificate yet
		letsEncryptX1Cert := []byte(`-----BEGIN CERTIFICATE-----
 MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
 -----END CERTIFICATE-----`)
		certPool.AppendCertsFromPEM(letsEncryptX1Cert)
		letsEncryptX1Cert = nil
	}

	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf(
				"Unable to use certificate [%v] (key: [%v]): %v",
				clientCreds.clientCert,
				clientCreds.clientKey,
				err,
			)
		} else {
			xCert = cert
		}
	}

	tlsClientConfig := tls.Config{}
	tlsClientConfig.RootCAs = certPool
	tlsClientConfig.Certificates = []tls.Certificate{xCert}
	certPool = nil
	certPoolErr = nil
	xCert = tls.Certificate{}
	tlsClientConfig.InsecureSkipVerify = false

	if xTransport.keyLogWriter != nil {
		tlsClientConfig.KeyLogWriter = xTransport.keyLogWriter
	}

	if xTransport.tlsDisableSessionTickets {
		tlsClientConfig.SessionTicketsDisabled = xTransport.tlsDisableSessionTickets
		tlsClientConfig.ClientSessionCache = nil
	} else {
		tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}

	if xTransport.CSHandleError == 3 {
		xTransport.MaxVersion = tls.VersionTLS12
		tlsClientConfig.MaxVersion = tls.VersionTLS12
	} else {
		xTransport.MaxVersion = tls.VersionTLS13
		tlsClientConfig.MaxVersion = tls.VersionTLS13
	}
	if xTransport.keepCipherSuite == true {
		if xTransport.tlsCipherSuite != nil && len(xTransport.tlsCipherSuite) > 0 {
			tls13 := map[int]struct{}{
				198: {}, 199: {}, 4865: {}, 4866: {}, 4867: {},
				4868: {}, 4869: {}, 49332: {}, 49333: {},
			}
			tlsSecure := map[int]struct{}{
				4865: {}, 4866: {}, 4868: {}, 49195: {}, 49196: {},
				49199: {}, 49200: {}, 52392: {}, 52393: {},
			}
			var is_tls13 = 0
			var Ciphers = 0
			for Ciphers = 0; Ciphers < len(xTransport.tlsCipherSuite); {
				CSuite := int(xTransport.tlsCipherSuite[Ciphers])
				// remove non-secure cipher suites
				if _, ok := tlsSecure[CSuite]; !ok {
					xTransport.tlsCipherSuite[Ciphers] = xTransport.tlsCipherSuite[len(xTransport.tlsCipherSuite)-1]
					xTransport.tlsCipherSuite = xTransport.tlsCipherSuite[:len(xTransport.tlsCipherSuite)-1]
					continue
				}
				// mark TLS 1.3 presence
				if _, ok := tls13[CSuite]; ok {
					is_tls13 += 1
				}
				Ciphers += 1
			}
			if is_tls13 != Ciphers {
				dlog.Info(" [ ! ] Explicit cipher suite configured downgrading to TLS 1.2")
				xTransport.MaxVersion = tls.VersionTLS12
				tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
				tlsClientConfig.MaxVersion = tls.VersionTLS12
			} else {
				dlog.Notice(" [ ! ] Configured cipher suites is unsupported with TLS 1.2")
				xTransport.tlsCipherSuite = DefaultTLSCipherSuites()
				dlog.Noticef(" [ + ] Added default secure cipher suites: %v", xTransport.tlsCipherSuite)
				xTransport.CSHandleError = 2
				xTransport.MaxVersion = tls.VersionTLS12
				tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
				tlsClientConfig.MaxVersion = tls.VersionTLS12
			}
		} else if xTransport.CSHandleError == 0 {
			xTransport.CSHandleError = 2
			xTransport.MaxVersion = tls.VersionTLS12
			tlsClientConfig.MaxVersion = tls.VersionTLS12
		}
	}

	transport := &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        xTransport.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			// resolveAndUpdateCache() is always called in `Fetch()` before the `Dial()`
			// method is used, so that a cached entry must be present at this point.
			cachedIP, _, _ := xTransport.loadCachedIP(host)
			if cachedIP != nil {
				ipv4 := cachedIP.To4()
				if ipv4 != nil {
					ipOnly = ipv4.String()
				} else if xTransport.useIPv6 {
					ipOnly = "[" + cachedIP.String() + "]"
				}
			} else {
				dlog.Infof("[%s] IP address was not cached in DialContext", host)
			}
			addrStr = ipOnly + ":" + strconv.Itoa(port)
			if xTransport.proxyDialer == nil {
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout}
				return dialer.DialContext(ctx, network, addrStr)
			} else {
				return (*xTransport.proxyDialer).Dial(network, addrStr)
			}
		},
	}

	if xTransport.httpProxyFunction != nil {
		transport.Proxy = xTransport.httpProxyFunction
	}

	transport.TLSClientConfig = &tlsClientConfig
	if http2Transport, _ := http2.ConfigureTransports(transport); http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
	xTransport.transport = transport

	if xTransport.http3 {
		dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			dlog.Infof("Dialing for H3: [%v]", addrStr)
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			cachedIP, _, _ := xTransport.loadCachedIP(host)
			network := "udp4"
			if cachedIP != nil {
				if ipv4 := cachedIP.To4(); ipv4 != nil {
					ipOnly = ipv4.String()
				} else {
					ipOnly = "[" + cachedIP.String() + "]"
					network = "udp6"
				}
			} else {
				dlog.Infof("[%s] IP address was not cached in H3 context", host)
				if xTransport.useIPv4 {
					network = "udp4"
				}
				if xTransport.useIPv6 && (preferIPv6 || !xTransport.useIPv4) {
					network = "udp6"
				}
			}
			addrStr = ipOnly + ":" + strconv.Itoa(port)

			udpAddr, err := net.ResolveUDPAddr(network, addrStr)
			if err != nil {
				return nil, err
			}

			udpConn, err := net.ListenUDP(network, nil)
			if err != nil {
				return nil, err
			}

			tlsCfg.ServerName = host

			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				conn.CloseWithError(0, err.Error())
				return nil, err
			}
			return conn, nil
		}
		h3Transport := &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    &tlsClientConfig,
			Dial:               dial,
		}
		xTransport.h3Transport = h3Transport
	}
}

// Resolve using the system resolver: net.LookupHost
func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	if !xTransport.ignoreSystemDNS {
		ipa, err := net.LookupIP(host)
		if err == nil {
			if returnIPv4 && returnIPv6 {
				return ipa, SystemResolverIPTTL, nil
			}
			ips := make([]net.IP, 0)
			for _, ip := range ipa {
				ipv4 := ip.To4()
				if returnIPv4 && ipv4 != nil {
					ips = append(ips, ipv4)
				}
				if returnIPv6 && ipv4 == nil {
					ips = append(ips, ip)
				}
			}
			return ips, SystemResolverIPTTL, err
		}
		return nil, SystemResolverIPTTL, err
	} else {
		dlog.Warnf(" [ ! ] ( resolveUsingSystem )      :Resolving using system resolver is disabled but the function is called. ( Host: %v )", host)
	}
	return nil, 0, nil
}

func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	dnsClient := dns.Client{Net: proto, ReadTimeout: ResolverReadTimeout}
	queryType := make([]uint16, 0, 2)
	if returnIPv4 {
		queryType = append(queryType, dns.TypeA)
	}
	if returnIPv6 {
		queryType = append(queryType, dns.TypeAAAA)
	}
	var rrTTL uint32
	for _, rrType := range queryType {
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), rrType)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(&msg, resolver); err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == rrType {
					switch rrType {
					case dns.TypeA:
						if xTransport.useIPv4 {
							ips = append(ips, answer.(*dns.A).A)
						}
					case dns.TypeAAAA:
						if xTransport.useIPv6 {
							ips = append(ips, answer.(*dns.AAAA).AAAA)
						}
					}
					rrTTL = answer.Header().Ttl
				}
			}
		}
	}
	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}
	return ips, ttl, err
}

func (xTransport *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	err = errors.New("empty resolvers")
	if len(resolvers) == 0 {
		dlog.Info(err)
	}
	// The resolver first tries all the specified IPs through 1 protocol and if they fail then it will try with the second protocol. TCP -> UDP
	for i, resolver := range resolvers {
		if resolver != "" && len(resolver) > 0 {
			ips, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
		} else {
			err = errors.New("empty resolver")
		}
		if err == nil && len(ips) > 0 {
			dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
			if i > 0 {
				resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
			}
			break
		} else {
			dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, err)
		}
	}
	return ips, ttl, err
}

func (xTransport *XTransport) resolve(host string, is_STAMP, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}
	if xTransport.internalResolverReady {
		for _, proto := range protos {
			ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.internalResolvers, xTransport.useIPv4, xTransport.useIPv6)
			if err == nil {
				dlog.Infof("- - - Updating complete with protocol: %v   || IP Address: %v", proto, ips)
				break
			}
		}
	} else {
		err = errors.New("( ! ) Service is not usable yet")
		dlog.Notice(err)
	}
	if err != nil {
		if xTransport.NoFallback == false || is_STAMP {
			if xTransport.bootstrapResolvers != nil && len(xTransport.bootstrapResolvers) > 0 {
				for _, proto := range protos {
					dlog.Noticef(
						"Resolving server host [%s] using bootstrap resolvers over %s",
						host,
						proto,
					)
					ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.bootstrapResolvers, xTransport.useIPv4, xTransport.useIPv6)
					if err == nil {
						break
					}
				}
			} else {
				err = errors.New("( ! ) Bootstrap resolvers is empty")
				dlog.Notice(err)
			}
		}

		if err != nil && xTransport.NoFallback == false {
			if xTransport.ignoreSystemDNS == false {
				dlog.Noticef(" ( + ) Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
				err = nil
				ips, ttl, err = xTransport.resolveUsingSystem(host, xTransport.useIPv4, xTransport.useIPv6)
				if err != nil {
					err = errors.New("( ! ) System DNS error")
					dlog.Notice(err)
				}
			} else if xTransport.ignoreSystemDNS == true {
				if len(xTransport.bootstrapResolvers) > 0 {
					dlog.Noticef(" ( ! ) Bootstrap resolver failled and system dns is ignored")
				} else {
					dlog.Noticef(" ( ! ) Bootstrap resolvers is not set and system dns is ignored")
				}
			}
		}
	}
	return ips, ttl, err
}

// If a name is not present in the cache, resolve the name and update the cache
func (xTransport *XTransport) resolveAndUpdateCache(host string, is_STAMP bool) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}
	if ParseIP(host) != nil {
		return nil
	}
	cachedIPs, expired, updating := xTransport.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}
	xTransport.markUpdatingCachedIP(host)

	ips, ttl, err := xTransport.resolve(host, is_STAMP, xTransport.useIPv4, xTransport.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}
	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale [%v] cached address for a grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}
	if err != nil {
		return err
	}
	if len(selectedIPs) == 0 {
		if !xTransport.useIPv4 && xTransport.useIPv6 {
			dlog.Warnf("no IPv6 address found for [%s]", host)
		} else if xTransport.useIPv4 && !xTransport.useIPv6 {
			dlog.Warnf("no IPv4 address found for [%s]", host)
		} else {
			dlog.Errorf("no IP address found for [%s]", host)
		}
		return nil
	}
	xTransport.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

func (xTransport *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if rebuildingTransport {
		return nil, 0, nil, 0, errors.New("rebuilding transport")
	}
	if timeout <= 0 || timeout > xTransport.timeout {
		timeout = xTransport.timeout
	}

	// Setup HTTP client with timeout and transport
	client := http.Client{
		Transport: xTransport.transport,
		Timeout:   timeout,
	}
	host, port := ExtractHostAndPort(url.Host, 443)

	// Reject .onion if no proxy dialer
	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("onion service is not reachable without Tor")
	}

	hasAltSupport := false
	is_http2 := true

	if xTransport.http3 == true && xTransport.h3Transport != nil {
		is_http2 = false
		if xTransport.http3Probe {
			// Always try HTTP/3 first when http3_probe is enabled,
			// without checking for Alt-Svc
			client.Transport = xTransport.h3Transport
			dlog.Infof("Probing HTTP/3 transport for [%s]", url.Host)
		} else {
			// Otherwise use traditional Alt-Svc detection
			xTransport.altSupport.RLock()
			var altPort uint16
			altPort, hasAltSupport = xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			if hasAltSupport && altPort > 0 { // altPort > 0 ensures we're not in the negative cache
				if int(altPort) == port {
					client.Transport = xTransport.h3Transport
					dlog.Infof("Using HTTP/3 transport for [%s]", url.Host)
				} else {
					hasAltSupport = false
					dlog.Infof("Alt support dropped because port does not match the host port.")
				}
			}
		}
	}

	header := map[string][]string{"User-Agent": {xTransport.UserAgent}}
	if len(accept) > 0 {
		header["Accept"] = []string{accept}
	}
	if len(contentType) > 0 {
		header["Content-Type"] = []string{contentType}
	}
	header["Cache-Control"] = []string{"max-stale"}

	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		if qs.Has("body_hash") {
			qs.Set("body_hash", hex.EncodeToString(h[:32]))
		} else {
			qs.Add("body_hash", hex.EncodeToString(h[:32]))
		}
		url2 := *url
		url2.RawQuery = qs.Encode()
		url = &url2
	} else if compress { // COMPRESSED GET REQUEST
		header["Accept-Encoding"] = []string{"gzip"}
	}

	// Check if it is Stamp
	is_STAMP := false
	if strings.Contains(url.String(), ".md") {
		is_STAMP = true
	}

	if rebuildingTransport {
		return nil, 0, nil, 0, errors.New("rebuilding transport")
	}
	// Resolve host with caching
	if err := xTransport.resolveAndUpdateCache(host, is_STAMP); err != nil {
		dlog.Errorf(
			"Unable to resolve [%v] - Make sure that the system resolver works, or that `bootstrap_resolvers` has been set to resolvers that can be reached",
			host,
		)
		return nil, 0, nil, 0, err
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  true,
	}

	if body != nil {
		if int64(len(*body)) <= int64(MaxDNSPacketSize) {
			req.ContentLength = int64(len(*body))
		} else {
			return nil, 0, nil, 0, errors.New("request is bigger than allowed dns packet size")
		}
		if req.ContentLength > 0 && req.ContentLength == int64(len(*body)) {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		} else {
			return nil, 0, nil, 0, errors.New("request failed: Incorrect request size")
		}
	} else if req.Method == "POST" {
		return nil, 0, nil, 0, errors.New("request failed: Empty body")
	}

	if rebuildingTransport {
		return nil, 0, nil, 0, errors.New("rebuilding transport")
	}
	// Send request and measure RTT
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	h3_dropped := false

	// Handle HTTP/3 error case - fallback to HTTP/2 when HTTP/3 fails
	if err != nil && client.Transport == xTransport.h3Transport && is_http2 == false {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		}

		// Add server to negative cache when HTTP/3 fails
		xTransport.altSupport.Lock()
		xTransport.altSupport.cache[url.Host] = 0 // 0 port means HTTP/3 failed and should not be tried again
		xTransport.altSupport.Unlock()

		// Retry with HTTP/2
		if xTransport.RetryWith2 && xTransport.http3 == true {
			if rebuildingTransport {
				client.CloseIdleConnections()
				return nil, 0, nil, 0, errors.New("rebuilding transport")
			}
			tTLS := resp.TLS.CipherSuite
			if req.TLS.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 && req.TLS.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 && tTLS != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 && tTLS != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
				h3_dropped = true
				client.Transport = xTransport.transport
				start = time.Now()
				resp, err = client.Do(req)
				rtt = time.Since(start)
			}
		}
	}

	statusCode := 503
	if resp != nil {
		if resp.StatusCode < 200 || resp.StatusCode > 299 { // Response is not in OK range = Error
			err = errors.New(resp.Status)
		} else {
			statusCode = resp.StatusCode
		}
		if strings.Contains(resp.Proto, "/1") || (strings.Contains(resp.Proto, "/3") && is_http2 == true) || (strings.Contains(resp.Proto, "/2") && is_http2 == false) {
			protocolError := errors.New("request failed: Protocol miss match")
			return nil, 0, nil, 0, protocolError
		}
	} else if err == nil { // No response when no error = Error
		err = errors.New("webserver returned an error")
	}

	TLSVersion := xTransport.MaxVersion
	// Controlled TLS Drop
	if (xTransport.MaxVersion == tls.VersionTLS13 && xTransport.DropTLS13 == true) || (xTransport.MaxVersion == tls.VersionTLS12 && xTransport.DropTLS13 == true) {
		if resp.TLS != nil {
			if reflect.TypeOf(resp.TLS.Version) == reflect.TypeOf(uint16(0)) {
				TLSVersion = resp.TLS.Version
			}
			if TLSVersion == tls.VersionTLS13 && xTransport.DropTLS13 == true {
				err = errors.New("handshake failure")
			} else if TLSVersion == tls.VersionTLS12 && xTransport.DropTLS12 == true {
				err = errors.New("handshake failure")
			}
		} else {
			err = errors.New("handshake failure")
		}
	}

	// Handle TLS Cipher Suite errors
	if err != nil {
		dlog.Infof(" ( ! ) HTTP client error: [%v] - closing idle connections", err)
		client.CloseIdleConnections()
		xTransport.transport.CloseIdleConnections()
		getErrDetails := err.Error()
		if rtt > timeout {
			dlog.Info("Connection timeout exceeded")
		}
		if xTransport.MaxVersion == tls.VersionTLS13 && TLSVersion == tls.VersionTLS13 { // Fall to TLS1.2 with TLS1.3 error
			if strings.Contains(getErrDetails, "handshake failure") {
				if xTransport.CSHandleError == 0 && rtt < timeout {
					if xTransport.tlsCipherSuite == nil {
						xTransport.CSHandleError = 3
					} else {
						xTransport.CSHandleError = 4
					}
					xTransport.keepCipherSuite = true
					xTransport.rebuildTransport()
				}
			}
		} else if xTransport.MaxVersion == tls.VersionTLS12 && TLSVersion == tls.VersionTLS12 {
			if xTransport.keepCipherSuite == true {
				if (strings.Contains(getErrDetails, "handshake failure") || strings.Contains(getErrDetails, "tls: error decoding message")) && rtt < timeout {
					switch xTransport.CSHandleError {
					case 0:
						dlog.Warnf("TLS 1.2 configured cipher suite failed (You can try changing or deleting the tls_cipher_suite value in the configuration file). Adding more Cipher Suites.")
						xTransport.CSHandleError = 1
						xTransport.tlsCipherSuite = DefaultTLSCipherSuites()
						xTransport.keepCipherSuite = true
					case 1: // TLS 1.2 even after Cipher Suites failed upgrade
						if hasTLSConnected < 3 {
							dlog.Info("TLS 1.2 configured cipher suites failed. Upgrading to TLS 1.3")
							xTransport.CSHandleError = 0
							xTransport.keepCipherSuite = false
						} else {
							// TODO: Add setting to enable or not upgrade if TLS failed one after another after successful connection with this CipherSuite
						}
					case 2:
						dlog.Info("Dynamically adjusted server used Cipher Suite have failed. Adding more Cipher Suites for TLS 1.2")
						xTransport.CSHandleError = 1
						xTransport.tlsCipherSuite = DefaultTLSCipherSuites()
						xTransport.keepCipherSuite = true
						hasTLSConnected = 0
					case 3: // No Cipher Suite at start up add server Cipher Suite
						if resp != nil { // Usually we won't configure TLS through here from the server so ignore stamp server check and add TLS if exist to bypass custom drop lock
							if resp.TLS != nil && len([]uint16{resp.TLS.CipherSuite}) > 0 {
								if xTransport.tlsCipherSuite == nil {
									xTransport.tlsCipherSuite = []uint16{resp.TLS.CipherSuite}
									xTransport.transport.TLSClientConfig.CipherSuites = []uint16{resp.TLS.CipherSuite}
									xTransport.keepCipherSuite = true
									xTransport.CSHandleError = 2
									dlog.Infof("No TLS configured. Adding connections specified TLS to Cipher Suite:  %v", xTransport.tlsCipherSuite)
									hasTLSConnected = 0
								} else {
									dlog.Warn("No TLS configured and server TLS is not applicable because client cipher suite is not empty.")
								}
							} else {
								dlog.Warn("No TLS configured and server TLS is not applicable because TLS is empty.")
							}
						} else {
							dlog.Warn("No TLS configured and server TLS is not applicable because response is empty.")
						}
					case 4:
						dlog.Warnf("TLS handshake failure with cipher suite: %v - Try changing or deleting the tls_cipher_suite value in the configuration file", xTransport.tlsCipherSuite)
						xTransport.tlsCipherSuite = DefaultTLSCipherSuites()
						xTransport.keepCipherSuite = true
					default: // TLS 1.2 failed and TLS 1.3 failed loop
						dlog.Warnf("TLS handshake failure with cipher suite: %v - Try changing or deleting the tls_cipher_suite value in the configuration file", xTransport.tlsCipherSuite)
					}
					xTransport.rebuildTransport()
				}
			}
		} else {
			dlog.Warn("unexpected TLS Version")
		}
		return nil, 0, nil, 0, err
	}

	// Check if it is HTTP3
	if h3_dropped == false && is_http2 == false && xTransport.http3 == true && xTransport.h3Transport != nil && !hasAltSupport && resp != nil {
		// Check if there's entry in negative cache when using http3_probe
		skipAltSvcParsing := false
		if xTransport.http3Probe {
			xTransport.altSupport.RLock()
			altPort, inCache := xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			// If server is in negative cache (altPort == 0), don't attempt to parse Alt-Svc header
			if inCache && altPort == 0 {
				dlog.Infof("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", url.Host)
				skipAltSvcParsing = true
			}
		}

		if !skipAltSvcParsing {
			if alt, found := resp.Header["Alt-Svc"]; found {
				dlog.Infof("Alt-Svc [%s]: [%s]", url.Host, alt)
				altPort := uint16(port & 0xffff)
				for i, xalt := range alt {
					for j, v := range strings.Split(xalt, ";") {
						if i >= 8 || j >= 16 {
							break
						}
						v = strings.TrimSpace(v)
						if strings.HasPrefix(v, "h3=\":") {
							v = strings.TrimPrefix(v, "h3=\":")
							v = strings.TrimSuffix(v, "\"")
							if xAltPort, err := strconv.ParseUint(v, 10, 16); err == nil && xAltPort <= 65535 {
								altPort = uint16(xAltPort)
								dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
								break
							}
						}
					}
				}
				xTransport.altSupport.Lock()
				xTransport.altSupport.cache[url.Host] = altPort
				dlog.Debugf("Caching altPort for [%v]", url.Host)
				xTransport.altSupport.Unlock()
			}
		}
	}

	// Process the response
	if resp != nil {
		response_tls := resp.TLS
		if response_tls == nil {
			err := errors.New("no tls")
			return nil, 0, nil, 0, err
		}
		current_tls := response_tls.CipherSuite
		tls_version := response_tls.Version
		tls13_safe := "4865 4866 4868"
		tls12_safe := "52393 49200 49199 49196 49195"
		if tls_version == uint16(xTransport.MaxVersion) {
			ignore_response := true
			if tls_version == 0x0304 { // Using TLS 1.3
				if strings.Contains(tls13_safe, strconv.Itoa(int(current_tls))) {
					ignore_response = false
				} else {
					err := errors.New("unsafe TLS usage with tls version 1.3")
					return nil, 0, nil, 0, err
				}
			} else if tls_version == 0x0303 { // Using TLS 1.2
				if strings.Contains(tls12_safe, strconv.Itoa(int(current_tls))) {
					if xTransport.tlsCipherSuite == nil { // No Cipher Suite at start up add server Cipher Suite
						if xTransport.CSHandleError == 3 {
							// Don't add TLS from public resolver domains it may be incompatible with resolver
							if !is_STAMP {
								xTransport.tlsCipherSuite = []uint16{current_tls}
								xTransport.transport.TLSClientConfig.CipherSuites = []uint16{current_tls}
								xTransport.keepCipherSuite = true
								xTransport.CSHandleError = 2
								dlog.Infof(" ( + ) TLS: Not configured. Adding connections specified tls to Cipher Suite: [ %v ]", xTransport.tlsCipherSuite)
								xTransport.rebuildTransport()
							}
						}
					}
					if hasTLSConnected >= 0 {
						if hasTLSConnected < 10 {
							hasTLSConnected += 1
						}
					} else {
						hasTLSConnected = 0
					}
					ignore_response = false
				} else { // Manage other TLS
					err := errors.New("unsafe tls Usage")
					return nil, 0, nil, 0, err
				}
			} else { // Drop other TLS versions
				err := errors.New("unexpected tls Version")
				return nil, 0, nil, 0, err
			}
			if ignore_response == false {
				if resp.Body != nil {
					var bodyReader io.ReadCloser = resp.Body
					// DECODE
					if compress && resp.Header.Get("Content-Encoding") == "gzip" {
						bodyReader, err = gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
						if err != nil {
							_ = resp.Body.Close()
							return nil, statusCode, response_tls, rtt, err
						}
						defer bodyReader.Close()
					} else {
						compresserr := error(nil)
						resp_enc_header_length := len(resp.Header.Get("Content-Encoding"))
						if !compress && resp_enc_header_length > 0 {
							compresserr = errors.New("response has compression without requesting it")
						} else if compress && resp_enc_header_length > 0 {
							compresserr = errors.New("compress is set but response has incorrect encoding")
						} else if compress {
							compresserr = errors.New("compress is set but response has no encoding")
						}
						if compresserr != nil {
							return nil, 0, nil, 0, compresserr
						}
					}
					bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
					errbc := resp.Body.Close()
					if errbc != nil {
						bin = nil
						return nil, 0, nil, 0, errbc
					}
					if err != nil {
						return nil, statusCode, response_tls, rtt, err
					}
					return bin, statusCode, response_tls, rtt, err
				}
			} else {
				err := errors.New("response ignored")
				return nil, 0, nil, rtt, err
			}
		} else {
			err := errors.New("unexpected tls usage")
			return nil, statusCode, response_tls, rtt, err
		}
	} else {
		err := errors.New("empty response")
		return nil, 0, nil, 0, err
	}

	// Return error
	err = errors.New("failed body")
	return nil, statusCode, nil, rtt, err
}

func (xTransport *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, true)
}

func (xTransport *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, false)
}

func (xTransport *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	dlog.Infof("Doing Post Request with URL: %v", url)
	return xTransport.Fetch("POST", url, accept, contentType, body, timeout, false)
}

func (xTransport *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, &body, timeout)
}

func (xTransport *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

func (xTransport *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
