package net

import (
	"context"
	"fmt"
	"net"
	"net/url"

	libnet "github.com/fatedier/golib/net"
	"golang.org/x/net/websocket"
)

func DialHookCustomTLSHeadByte(enableTLS bool, disableCustomTLSHeadByte bool) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if enableTLS && !disableCustomTLSHeadByte {
			_, err := c.Write([]byte{byte(FRPTLSHeadByte)})
			if err != nil {
				return nil, nil, err
			}
		}
		return ctx, c, nil
	}
}

func DialHookWebsocket(protocol string, host string) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		scheme := protocol
		if scheme != "wss" {
			scheme = "ws"
		}
		authority := host
		if authority == "" {
			authority = addr
		}
		return DialHookWebsocketWithURL(scheme+"://"+authority+FrpWebsocketPath)(ctx, c, addr)
	}
}

// DialHookWebsocketWithURL uses the supplied WebSocket request URL over an
// already connected transport. The URL does not select the socket or TLS peer.
func DialHookWebsocketWithURL(requestURL string) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, _ string) (context.Context, net.Conn, error) {
		uri, err := url.Parse(requestURL)
		if err != nil {
			return nil, nil, err
		}
		if (uri.Scheme != "ws" && uri.Scheme != "wss") || uri.Host == "" {
			return nil, nil, fmt.Errorf("invalid WebSocket request URL: %q", requestURL)
		}
		origin := "http://" + uri.Host
		cfg, err := websocket.NewConfig(requestURL, origin)
		if err != nil {
			return nil, nil, err
		}
		conn, err := websocket.NewClient(cfg, c)
		if err != nil {
			return nil, nil, err
		}
		// Tunnel data is a raw byte stream, not UTF-8 text.
		conn.PayloadType = websocket.BinaryFrame
		return ctx, conn, nil
	}
}
