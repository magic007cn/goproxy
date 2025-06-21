package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"syscall"
	"os/signal"
	"crypto/tls"
	"io"	
	"gopkg.in/yaml.v3"
	"fmt"
	"bufio"
	"context"
	"encoding/base64"
	"net/url"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type Config struct {
	Proxy struct {
		Listen       string `yaml:"listen"`
		AllowHTTP    bool   `yaml:"allow_http"`
		TlsEnabled	 bool	`yaml:"tls_enabled"`
		ForceTls	 bool	`yaml:"force_tls"`
		CertFile     string `yaml:"cert_file"`
		KeyFile      string `yaml:"key_file"`
		TlsMinVersion string `yaml:"tls_min_version"`
	} `yaml:"proxy"`

	Rules []struct {
		Domain        string   `yaml:"domain"`
		AllowedPaths  []string `yaml:"allowed_paths"`
		DenyPaths     []string `yaml:"deny_paths"`
		AllowedMethods []string `yaml:"allowed_methods"`
		StripPrefix   bool     `yaml:"strip_prefix"`
	} `yaml:"rules"`

	AccessControl struct {
		AllowedIPs  []string `yaml:"allowed_ips"`
		RequireAuth bool     `yaml:"require_auth"`
		AuthUser    string   `yaml:"auth_user"`
		AuthPass    string   `yaml:"auth_pass"`
	} `yaml:"access_control"`
}

var (
	allowedPathRegex = make(map[string][]*regexp.Regexp)
	denyPathRegex    = make(map[string][]*regexp.Regexp)
	config           Config
)

func main() {
	loadConfig("config.yaml")
	compileRegexPatterns()

	tlsConfig, cm, err := createTLSConfig(config.Proxy.CertFile, config.Proxy.KeyFile, config.Proxy.TlsMinVersion)
	if err != nil {
		log.Fatalf("failed to load TLS Certificate: %v", err)
	}
	if cm != nil {
		go cm.WatchChanges()
	}

	server := &http.Server{
		Addr:    config.Proxy.Listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				// 检查WebSocket升级请求
				if isWebSocketUpgrade(r) {
					handleWebSocketProxy(w, r)
					return
				}
				// 检查是否是h2c升级请求
				if isH2CUpgrade(r) {
					handleH2CUpgrade(w, r)
					return
				}
				if r.Method == http.MethodConnect {
					handleHTTPS(w, r)
				} else {
					handleHTTP(w, r)
				}
		})
		handler(w, r)
		}),	
		TLSConfig: tlsConfig,	
		// 配置HTTP/2支持
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	// 配置HTTP/2服务器支持
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		log.Fatal("HTTP/2配置失败:", err)
	}
	
	setupConfigReload()

	log.Printf("Starting HTTP proxy server on %s\n", config.Proxy.Listen)
	log.Fatal(server.ListenAndServe())
}
func createTLSConfig(certFile, keyFile, minTLS string) (*tls.Config, *CertificateManager, error) {
	var minVersion uint16
    switch minTLS {
    case "1.3":
        minVersion = tls.VersionTLS13
    case "1.2":
        minVersion = tls.VersionTLS12
    case "1.0":
        minVersion = tls.VersionTLS10
    default:
        minVersion = tls.VersionTLS12
    }
	if ! config.Proxy.TlsEnabled {
		return &tls.Config{
			MinVersion:   minVersion,
			NextProtos:   []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		}, nil,nil
	}
    if certFile == "" || keyFile == "" {
        return nil, nil,fmt.Errorf("certificate and key files must be specified")
    }
	cm, err := NewCertificateManager(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   minVersion,
		NextProtos:   []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cm.GetCertificate(), nil
		},
	}, cm, nil
}

func loadConfig(filename string) {
	config.Proxy.Listen = "0.0.0.0:28080"
	config.Proxy.AllowHTTP = false
	config.Proxy.TlsEnabled = true
	config.Proxy.ForceTls = false
	config.Proxy.CertFile = "cert.pem"
	config.Proxy.KeyFile = "key.pem"
	config.AccessControl.RequireAuth = false
	config.Proxy.TlsMinVersion = "1.2"

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}
}
func setupConfigReload() {
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGHUP)
    go func() {
        for range sig {
            log.Println("Reloading configuration...")
            loadConfig("config.yaml")
            compileRegexPatterns()
        }
    }()
}
func compileRegexPatterns() {
	for _, rule := range config.Rules {
		var allowed []*regexp.Regexp
		for _, pattern := range rule.AllowedPaths {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Fatalf("Error compiling allowed path regex %s: %v", pattern, err)
			}
			allowed = append(allowed, re)
		}
		allowedPathRegex[rule.Domain] = allowed

		var denied []*regexp.Regexp
		for _, pattern := range rule.DenyPaths {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Fatalf("Error compiling denied path regex %s: %v", pattern, err)
			}
			denied = append(denied, re)
		}
		denyPathRegex[rule.Domain] = denied
	}
}

func isRequestAllowed(r *http.Request) bool {
    // 1. 记录完整请求信息
    //log.Printf("Received request: %+v", r)

    // 2. 检查IP白名单
    if !isIPAllowed(r.RemoteAddr) {
        log.Printf("IP %s not in allowed list", r.RemoteAddr)
        return false
    }
    
    // 3. 查找匹配规则
    rule, found := findMatchingRule(r.Host)
    if !found {
        log.Printf("No rule found for host: %s", r.Host)
        return false
    }
    
    // 4. 检查HTTP方法
    if !isMethodAllowed(r.Method, rule.AllowedMethods) {
        log.Printf("Method %s not allowed for host %s", r.Method, r.Host)
        return false
    }
    
    // 5. 检查URL路径
    if !isPathAllowed(r.URL.Path, rule) {
        log.Printf("Path %s not allowed for host %s", r.URL.Path, r.Host)
        return false
    }
    return true
}

func isIPAllowed(remoteAddr string) bool {
    //clientIP, _, _ := net.SplitHostPort(remoteAddr)
    //log.Printf("Client IP: %s, Allowed IPs: %v", clientIP, config.AccessControl.AllowedIPs)

	if len(config.AccessControl.AllowedIPs) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range config.AccessControl.AllowedIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func findMatchingRule(host string) (*struct {
	Domain        string   `yaml:"domain"`
	AllowedPaths  []string `yaml:"allowed_paths"`
	DenyPaths     []string `yaml:"deny_paths"`
	AllowedMethods []string `yaml:"allowed_methods"`
	StripPrefix   bool     `yaml:"strip_prefix"`
}, bool) {
	domain := strings.Split(host, ":")[0]

	for _, rule := range config.Rules {
		if rule.Domain == domain {
			return &rule, true
		}
	}

	return nil, false
}

func isMethodAllowed(method string, allowedMethods []string) bool {
	//log.Printf("Checking method %s against allowed methods %v", method, allowedMethods)

	if len(allowedMethods) == 0 {
		return true
	}

	for _, m := range allowedMethods {
		if strings.EqualFold(method, m) {
			return true
		}
	}

	return false
}

func isPathAllowed(path string, rule *struct {
	Domain        string   `yaml:"domain"`
	AllowedPaths  []string `yaml:"allowed_paths"`
	DenyPaths     []string `yaml:"deny_paths"`
	AllowedMethods []string `yaml:"allowed_methods"`
	StripPrefix   bool     `yaml:"strip_prefix"`
}) bool {
	//log.Printf("Checking path: %s against deny rules: %v", path, denyPathRegex[rule.Domain])
    for _, re := range denyPathRegex[rule.Domain] {
        if re.MatchString(path) {
            log.Printf("Path %s denied by rule %s", path, re.String())
            return false
        }
    }
	for _, re := range denyPathRegex[rule.Domain] {
		if re.MatchString(path) {
			return false
		}
	}

	if len(allowedPathRegex[rule.Domain]) == 0 {
		return true
	}

	for _, re := range allowedPathRegex[rule.Domain] {
		if re.MatchString(path) {
			return true
		}
	}

	return false
}
func isH2CUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade, http2-settings" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "h2c"
}
// authMiddleware 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {
		// 检查是否是 HTTPS 连接
		if config.Proxy.ForceTls {
			if r.TLS == nil {
				http.Error(w, "Only HTTPS connections are accepted", http.StatusForbidden)
				return
			}
		}
        // 如果未启用认证，直接放行
        if config.AccessControl.RequireAuth == false {
            next.ServeHTTP(w, r)
            return
        }

             // 1. 检查是否有认证头
			 authHeader := r.Header.Get("Proxy-Authorization") // 代理通常用这个头
			 if authHeader == "" {
				 authHeader = r.Header.Get("Authorization") // 也可能是这个
			 }
			 
			 if authHeader == "" {
				 w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authentication"`)
				 http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				 return
			 }
			 
			 // 2. 解析Basic Auth
			 username, password, ok := parseBasicAuth(authHeader)
			 if !ok {
				 http.Error(w, "Invalid authentication format", http.StatusBadRequest)
				 return
			 }
			 
			 // 3. 验证凭据
			 if username != config.AccessControl.AuthUser || password != config.AccessControl.AuthPass {
				 http.Error(w, "Invalid credentials", http.StatusForbidden)
				 return
			 }

        next.ServeHTTP(w, r)
    }
}
// 手动解析Basic Auth（比r.BasicAuth()更灵活）
func parseBasicAuth(auth string) (username, password string, ok bool) {
    const prefix = "Basic "
    if !strings.HasPrefix(auth, prefix) {
        return
    }
    
    decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
    if err != nil {
        return
    }
    
    pair := strings.SplitN(string(decoded), ":", 2)
    if len(pair) != 2 {
        return
    }
    
    return pair[0], pair[1], true
}
func parseTargetURL(r *http.Request) (*url.URL, error) {
	// 获取请求的目标地址
	target := r.URL.String()
	if !r.URL.IsAbs() {
		// 如果不是绝对路径，尝试从Host头获取
		if r.Host == "" {
			return nil, fmt.Errorf("non-absolute request and no Host header")
		}
		target = r.URL.Scheme + "://" + r.Host + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
	}

	// 解析URL
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// 如果没有指定scheme，默认为http
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}

	// 确保有端口号
	if targetURL.Port() == "" {
		if targetURL.Scheme == "https" {
			targetURL.Host = net.JoinHostPort(targetURL.Hostname(), "443")
		} else {
			targetURL.Host = net.JoinHostPort(targetURL.Hostname(), "80")
		}
	}

	return targetURL, nil
}

func handleH2CUpgrade(w http.ResponseWriter, r *http.Request) {
	if !isRequestAllowed(r) {
		http.Error(w, "Request not allowed", http.StatusForbidden)
		log.Printf("handleH2CUpgrade Request not allowed, r.URL: %v", r.URL)
		return
	}
	// 解析目标地址
	targetURL, err := parseTargetURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("handleH2CUpgrade解析目标地址失败, r.URL: %v", r.URL)
		return
	}
	log.Printf("handleH2CUpgrade protocol: %v, target: %v, header: %v", r.Proto, targetURL.String(), r.Header)
	if targetURL.Scheme == "http" && !config.Proxy.AllowHTTP {
		http.Error(w, "HTTP traffic not allowed", http.StatusForbidden)
		log.Printf("handleH2CUpgrade targetURL.Scheme == http && !config.Proxy.AllowHTTP, r.URL: %v", r.URL)
		return
	}
	// 劫持客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Hijack failed: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()
	proxyURL := strings.TrimSpace(os.Getenv("https_proxy"))
	dialer, err := createDialer(proxyURL, 15*time.Second,30*time.Second)
	if err != nil {
		log.Printf("create dialer error, proxyURL: %s, error: %v", proxyURL, err)
		http.Error(w, "connect error", http.StatusInternalServerError)
		return
	}
	
	// 连接目标服务器
	destConn, err :=dialer(r.Context(), "tcp", targetURL.Host)
	if err != nil {
		http.Error(w, "connect error", http.StatusInternalServerError)
		return
	}
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer destConn.Close()

	// 修改请求为绝对路径
	r.URL.Scheme = targetURL.Scheme
	r.URL.Host = targetURL.Host
	r.RequestURI = ""

	// 发送请求到目标服务器
	if err := r.Write(destConn); err != nil {
		log.Printf("Failed to send request: %v", err)
		return
	}

	// 读取目标服务器的响应
	resp, err := http.ReadResponse(bufio.NewReader(destConn), r)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return
	}
	defer resp.Body.Close()

	// 检查目标服务器是否接受h2c升级
	if resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.ToLower(resp.Header.Get("Upgrade")) == "h2c" {
		// 将升级响应转发给客户端
		if err := resp.Write(clientConn); err != nil {
			log.Printf("Failed to write upgrade response: %v", err)
			return
		}

		// 现在连接已升级为h2c，处理双向通信
		go transfer(destConn, clientConn)
		transfer(clientConn, destConn)
	} else {
		// 目标服务器不支持h2c，回退到普通HTTP
		if err := resp.Write(clientConn); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	}
	logRequest(r, http.StatusOK)
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// 验证CONNECT请求
	if !isRequestAllowed(r) {
		http.Error(w, "HTTPS request not allowed", http.StatusForbidden)
		return
	}
	log.Printf("handleHTTPS protocol: %v, target: %v, header: %v", r.Proto, r.URL.String(), r.Header)
	// 获取目标主机
	host := r.Host
	port:=r.URL.Port()
	if port==""{
		port="443"
	}	
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, port)
	}
	proxyURL := strings.TrimSpace(os.Getenv("https_proxy"))
	dialer, err := createDialer(proxyURL, 15*time.Second,30*time.Second)
	if err != nil {
		log.Printf("create dialer error, proxyURL: %s, error: %v", proxyURL, err)
		http.Error(w, "connect error", http.StatusInternalServerError)
		return
	}
	if proxyURL!=""{
		log.Printf("handle https connect to host %s via proxy %s", host, proxyURL)
	}
	// 连接目标服务器
	destConn, err :=dialer(r.Context(), "tcp", host)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Printf("connect to host %s error: %v", host, err)
		return
	}
	defer destConn.Close()

	// 响应客户端已建立连接
	w.WriteHeader(http.StatusOK)

	// 获取底层连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// 开始双向数据转发
	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
	logRequest(r, http.StatusOK)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !config.Proxy.AllowHTTP {
		http.Error(w, "HTTP traffic not allowed", http.StatusForbidden)
		return
	}	

	if !isRequestAllowed(r) {
		http.Error(w, "Request not allowed", http.StatusForbidden)
		return
	}

	// 修改请求以移除代理头部
	r.URL.Scheme = "http"
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.RequestURI = ""
	removeProxyHeaders(r.Header)

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不自动跟随重定向
		},
	}

	// 转发请求
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// 将响应体复制回客户端
	io.Copy(w, resp.Body)
	logRequest(r, resp.StatusCode)
}

// createDialer 创建一个可根据代理配置自动选择的 dialer
// proxyUrl: 代理服务器地址，如 "http://proxy.example.com:3128" 或 "socks5://user:pass@proxy:1080"
// timeout: 连接超时时间
// keepAlive: 连接保持时间
// 返回: 一个函数，签名为 func(ctx context.Context, network, addr string) (net.Conn, error)
func createDialer(proxyUrl string, timeout, keepAlive time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	// 如果没有代理配置，返回常规 dialer
	if proxyUrl == "" {
		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: keepAlive,
			DualStack: true,
		}
		return dialer.DialContext, nil
	}

	// 解析代理URL
	parsedProxyUrl, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}
	//log.Printf("createDialer parsedProxyUrl: %v", parsedProxyUrl)
	// 根据代理类型创建不同的 dialer
	switch parsedProxyUrl.Scheme {
	case "http", "https":
		return createHttpProxyDialer(parsedProxyUrl, timeout, keepAlive)
	case "socks5", "socks5h":
		return createSocks5ProxyDialer(parsedProxyUrl, timeout, keepAlive)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", parsedProxyUrl.Scheme)
	}
}

// createHttpProxyDialer 创建HTTP代理的dialer
func createHttpProxyDialer(proxyUrl *url.URL, timeout, keepAlive time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	// 创建基础 dialer
	baseDialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
		DualStack: true,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 对于HTTP代理，我们需要先连接到代理服务器
		proxyConn, err := baseDialer.DialContext(ctx, "tcp", proxyUrl.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy host:%s, error: %v", proxyUrl.Host, err)
		}

		// 如果是HTTPS目标，需要发送CONNECT请求
		if network == "tcp" {
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}

			// 添加代理认证信息
			if proxyUrl.User != nil {
				password, _ := proxyUrl.User.Password()
				auth := base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username() + ":" + password))
				connectReq.Header.Set("Proxy-Authorization", "Basic "+auth)
			}

			if err := connectReq.Write(proxyConn); err != nil {
				proxyConn.Close()
				return nil, fmt.Errorf("failed to send CONNECT request: %v", err)
			}

			// 读取代理响应
			br := bufio.NewReader(proxyConn)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				proxyConn.Close()
				return nil, fmt.Errorf("failed to read CONNECT response: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				proxyConn.Close()
				return nil, fmt.Errorf("proxy refused connection: %s", resp.Status)
			}

			// 如果代理返回了任何额外数据，需要保留在缓冲区
			if br.Buffered() > 0 {
				peeked, _ := br.Peek(br.Buffered())
				proxyConn = &bufferedConn{
					Conn:   proxyConn,
					peeked: peeked,
				}
			}
		}

		return proxyConn, nil
	}, nil
}

// createSocks5ProxyDialer 创建SOCKS5代理的dialer
func createSocks5ProxyDialer(proxyUrl *url.URL, timeout, keepAlive time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	// 使用第三方库实现SOCKS5代理
	// 需要先安装: go get golang.org/x/net/proxy
	dialer, err := proxy.SOCKS5("tcp", proxyUrl.Host, &proxy.Auth{
		User:     proxyUrl.User.Username(),
		Password: func() string { p, _ := proxyUrl.User.Password(); return p }(),
	}, &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
		DualStack: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	return dialer.(proxy.ContextDialer).DialContext, nil
}

// bufferedConn 用于处理代理返回的额外数据
type bufferedConn struct {
	net.Conn
	peeked []byte
	read   int
}

func (bc *bufferedConn) Read(b []byte) (n int, err error) {
	if bc.read < len(bc.peeked) {
		n = copy(b, bc.peeked[bc.read:])
		bc.read += n
		return n, nil
	}
	return bc.Conn.Read(b)
}
// isWebSocketUpgrade 检查是否是WebSocket升级请求
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "upgrade") && 
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// handleWebSocketProxy 处理WebSocket代理
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request) {
	if !isRequestAllowed(r) {
		http.Error(w, "Request not allowed", http.StatusForbidden)
		log.Printf("WebSocket Request not allowed, r.URL: %v", r.URL)
		return
	}
	// 解析目标URL
	target, err := url.Parse(r.URL.String())
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		log.Printf("WebSocket解析目标地址失败, r.URL: %v", r.URL)
		return
	}
	if target.Scheme == "ws" && !config.Proxy.AllowHTTP {
		http.Error(w, "HTTP traffic not allowed", http.StatusForbidden)
		log.Printf("WebSocket HTTP traffic not allowed, r.URL: %v", r.URL)
		return
	}
	proxyURL := strings.TrimSpace(os.Getenv("https_proxy"))
	dialer, err := createDialer(proxyURL, 15*time.Second,30*time.Second)
	if err != nil {
		log.Printf("create dialer error, proxyURL: %s, error: %v", proxyURL, err)
		http.Error(w, "connect error", http.StatusInternalServerError)
		return
	}
	// 连接目标服务器
	destConn, err :=dialer(r.Context(), "tcp", target.Host)
	if err != nil {
		http.Error(w, "Failed to connect to target server", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// 劫持客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 转发WebSocket升级请求到目标服务器
	err = r.Write(destConn)
	if err != nil {
		log.Printf("Failed to write request to target: %v", err)
		return
	}

	// 双向转发数据
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()

	<-done
	
	logRequest(r, 101)
}

// logRequest 记录请求信息
func logRequest(r *http.Request, statusCode int) {
	proto := r.Proto
	if r.ProtoMajor == 2 {
		proto = "HTTP/2"
	}
	
	log.Printf("[%s] %s %s %s %d %s", 
		time.Now().Format("2006-01-02 15:04:05"),
		r.Method, 
		r.URL.String(),
		proto,
		statusCode,
		r.RemoteAddr)
}

// removeProxyHeaders 移除代理相关的头部信息
func removeProxyHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("Connection")
}

// copyHeader 复制HTTP头部
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}