package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/samber/lo"
	"golang.org/x/net/websocket"
)

func connectorTestConfig(t *testing.T, address, protocol string) *v1.ClientCommonConfig {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &v1.ClientCommonConfig{ServerAddr: host, ServerPort: n}
	cfg.Complete()
	cfg.Transport.ProxyURL = ""
	cfg.Transport.Protocol = protocol
	cfg.Transport.TCPMux = lo.ToPtr(false)
	cfg.Transport.TLS.Enable = lo.ToPtr(false)
	return cfg
}

func TestConnectorWebsocketOptions(t *testing.T) {
	requests := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Host + r.URL.RequestURI()
		websocket.Handler(func(c *websocket.Conn) { _, _ = io.Copy(c, c) }).ServeHTTP(w, r)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := connectorTestConfig(t, u.Host, "wss")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	strict := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	// httptest's isolated certificate is valid for example.com, while the actual
	// socket address and HTTP authority are deliberately different.
	options := ConnectorOptions{TLSConfig: strict, WebsocketURL: "wss://gateway.example/domune/frp?channel=test"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connector := NewConnectorWithOptions(ctx, cfg, options)
	defer connector.Close()
	conn, err := connector.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{0, 255, 128}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 3)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string([]byte{0, 255, 128}) {
		t.Fatalf("binary echo = %v", response)
	}
	if got := <-requests; got != "gateway.example/domune/frp?channel=test" {
		t.Fatalf("request = %q", got)
	}
	if strict.ServerName != "example.com" || len(strict.NextProtos) != 0 {
		t.Fatal("caller TLS config mutated")
	}

	for _, tc := range []struct {
		name string
		tls  *tls.Config
	}{
		{"wrong-host", &tls.Config{RootCAs: roots, ServerName: "wrong.example"}},
		{"untrusted-certificate", &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewConnectorWithOptions(ctx, cfg, ConnectorOptions{TLSConfig: tc.tls, WebsocketURL: options.WebsocketURL})
			defer c.Close()
			if conn, err := c.Connect(); err == nil {
				conn.Close()
				t.Fatal("strict TLS accepted invalid identity")
			} else if tc.name == "wrong-host" {
				var hostnameError x509.HostnameError
				if !errors.As(err, &hostnameError) {
					t.Fatalf("TLS hostname error lost: %v", err)
				}
			}
		})
	}
}

func TestConnectorWebsocketDefault(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		websocket.Handler(func(c *websocket.Conn) { _, _ = io.Copy(c, c) }).ServeHTTP(w, r)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	c := NewConnector(context.Background(), connectorTestConfig(t, u.Host, "websocket"))
	defer c.Close()
	conn, err := c.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-paths; got != netpkg.FrpWebsocketPath {
		t.Fatalf("default path = %q", got)
	}
}

func TestConnectorTLSOptions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, tc := range []struct {
		name      string
		options   ConnectorOptions
		wantError bool
	}{
		{"strict-valid", ConnectorOptions{TLSConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}}, false},
		{"strict-wrong-host", ConnectorOptions{TLSConfig: &tls.Config{RootCAs: roots, ServerName: "wrong.example"}}, true},
		{"strict-untrusted", ConnectorOptions{TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"}}, true},
		// With no trusted CA, the upstream TLS default remains permissive.
		{"nil-upstream-default", ConnectorOptions{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := connectorTestConfig(t, u.Host, "tcp")
			cfg.Transport.TLS.Enable = lo.ToPtr(true)
			cfg.Transport.TLS.DisableCustomTLSFirstByte = lo.ToPtr(true)
			c := NewConnectorWithOptions(context.Background(), cfg, tc.options)
			defer c.Close()
			conn, err := c.Connect()
			if tc.wantError {
				if err == nil {
					conn.Close()
					t.Fatal("Connect accepted invalid TLS identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			if (err != nil) != tc.wantError {
				t.Fatalf("TLS write error = %v, want rejection %v", err, tc.wantError)
			}
			if !tc.wantError {
				response, err := io.ReadAll(conn)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(string(response), "ok") {
					t.Fatalf("response = %q", response)
				}
			}
		})
	}
}

func TestConnectorRawDialContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := connectorTestConfig(t, "target.example:7000", "tcp")
	var dialed bool
	c := NewConnectorWithOptions(context.Background(), cfg, ConnectorOptions{
		DialContext: func(ctx context.Context, network, destination string) (net.Conn, error) {
			if network != "tcp" || destination != "target.example:7000" {
				t.Fatalf("raw dial = %s %s", network, destination)
			}
			dialed = true
			return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		},
	})
	defer c.Close()
	conn, err := c.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !dialed {
		t.Fatal("custom dialer not used")
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted.Close()
}

func TestConnectorHandshakeCancellation(t *testing.T) {
	for _, protocol := range []string{"tcp", "wss"} {
		t.Run(protocol, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ready, closed := make(chan struct{}), make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					closed <- err
					return
				}
				defer c.Close()
				t.Cleanup(func() { c.Close() })
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				// Wait for the TLS ClientHello and then intentionally never respond.
				data := make([]byte, 4096)
				if _, err = c.Read(data); err != nil {
					closed <- err
					return
				}
				close(ready)
				_, err = io.Copy(io.Discard, c)
				closed <- err
			}()
			cfg := connectorTestConfig(t, ln.Addr().String(), protocol)
			cfg.Transport.TLS.Enable = lo.ToPtr(true)
			cfg.Transport.TLS.DisableCustomTLSFirstByte = lo.ToPtr(true)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c := NewConnectorWithOptions(ctx, cfg, ConnectorOptions{TLSConfig: &tls.Config{ServerName: "example.com"}, WebsocketURL: "wss://gateway.example/domune/frp"})
			defer c.Close()
			result := make(chan error, 1)
			go func() {
				conn, err := c.Connect()
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			select {
			case <-ready:
			case err := <-closed:
				t.Fatalf("fixture: %v", err)
			case <-time.After(time.Second):
				t.Fatal("TLS handshake not reached")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("dial error = %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("TLS handshake retained after cancellation")
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("socket retained: %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("raw TLS socket retained")
			}
		})
	}
}

func TestConnectorProxyCancellationUsesRawDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ready, closed := make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			closed <- err
			return
		}
		if req.Method != "CONNECT" || req.Host != "target.example:7000" || req.Header.Get("Proxy-Authorization") != "Basic YWxpY2U6cGFzc3dvcmQ=" {
			closed <- fmt.Errorf("unexpected CONNECT: %+v", req)
			return
		}
		close(ready)
		_, err = io.Copy(io.Discard, reader)
		closed <- err
	}()
	cfg := connectorTestConfig(t, "target.example:7000", "tcp")
	cfg.Transport.ProxyURL = "http://alice:password@" + ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := NewConnectorWithOptions(ctx, cfg, ConnectorOptions{DialContext: func(ctx context.Context, network, destination string) (net.Conn, error) {
		if network != "tcp" || destination != ln.Addr().String() {
			return nil, fmt.Errorf("raw dial bypassed proxy: %s %s", network, destination)
		}
		return (&net.Dialer{}).DialContext(ctx, network, destination)
	}})
	defer c.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := c.Connect()
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-ready:
	case err := <-closed:
		t.Fatalf("fixture: %v", err)
	case <-time.After(time.Second):
		t.Fatal("CONNECT not reached")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("proxy handshake retained")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("socket retained: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("proxy socket retained")
	}
}

func TestConnectorWSSPreservesTLSPolicyError(t *testing.T) {
	server := httptest.NewTLSServer(websocket.Handler(func(c *websocket.Conn) { _, _ = io.Copy(c, c) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	policyError := errors.New("custom TLS policy rejected peer")
	for _, requestURL := range []string{"wss://gateway.example/domune/frp", "invalid://gateway.example/domune/frp"} {
		t.Run(requestURL, func(t *testing.T) {
			c := NewConnectorWithOptions(context.Background(), connectorTestConfig(t, u.Host, "wss"), ConnectorOptions{
				TLSConfig:    &tls.Config{RootCAs: roots, ServerName: "example.com", VerifyConnection: func(tls.ConnectionState) error { return policyError }},
				WebsocketURL: requestURL,
			})
			defer c.Close()
			conn, err := c.Connect()
			if conn != nil {
				conn.Close()
			}
			if !errors.Is(err, policyError) {
				t.Fatalf("TLS policy must reject before WebSocket negotiation: %v", err)
			}
		})
	}
}
