//go:build lulutls_uquic

package outbound

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"lulutls/engine"
)

// TestLuluTLSAdapterLaneDQUIC drives the real LuluTLS adapter over lane D
// (QUIC/H3, uQUIC client) against a local engine quic server + TCP echo,
// proving lane D round-trips through the adapter when built -tags lulutls_uquic.
func TestLuluTLSAdapterLaneDQUIC(t *testing.T) {
	const sni = "www.bing.com"
	nodeKey := "laneD-node-key-xyz"
	userPSK := []byte("laneD-user-psk-123")
	tcpEcho := startTCPEcho(t)

	h := func(user string, network byte, addr string, remote net.Addr, st io.ReadWriteCloser) {
		defer st.Close()
		if network != engine.NetTCP {
			return
		}
		up, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer up.Close()
		go io.Copy(up, st)
		io.Copy(st, up)
	}

	srv, err := engine.New(engine.Config{Lane: "quic", Listen: "127.0.0.1:0", SNI: sni, NodeKey: []byte(nodeKey), Profile: "balanced"}, h)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	srv.SetUsers([]engine.User{{Name: "u1", PSK: userPSK}})
	if err := srv.Start(); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := strconv.Atoi(portStr)

	proxy, err := NewLuluTLS(LuluTLSOption{
		Name: "lulu-laneD", Server: host, Port: port,
		PSK: hex.EncodeToString(userPSK), NodeKey: nodeKey,
		Lane: "quic", SNI: sni, SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("NewLuluTLS: %v", err)
	}
	defer proxy.Close()

	eHost, ePortStr, _ := net.SplitHostPort(tcpEcho)
	ePort, _ := strconv.Atoi(ePortStr)
	md := &C.Metadata{NetWork: C.TCP, Host: eHost, DstPort: uint16(ePort)}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := proxy.DialContext(ctx, md)
	if err != nil {
		t.Fatalf("DialContext (lane D): %v", err)
	}
	defer c.Close()

	msg := []byte("lulutls-adapter-laneD-roundtrip")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("lane D echo mismatch: got %q want %q", got, msg)
	}
}
