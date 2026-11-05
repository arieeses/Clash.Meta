package outbound

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"lulutls/engine"
)

// TestLuluTLSAdapterEndToEnd stands up a real lulutls server (engine) with TCP
// and UDP echo upstreams, then drives the actual mihomo LuluTLS outbound
// (DialContext / ListenPacketContext) through it — proving the full client
// stack adapter -> lulutls/client -> engine -> target round-trips over the ws
// lane, the same wiring v2node uses.
func TestLuluTLSAdapterEndToEnd(t *testing.T) {
	const (
		sni  = "www.bing.com"
		uuid = "11111111-2222-3333-4444-555555555555"
	)
	master := []byte("4a3f8c1d2e5b6a7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3")
	nodeKey := []byte("9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0")
	psk := engine.DeriveUserPSK(master, uuid)

	// --- upstream echo targets ---
	tcpEcho := startTCPEcho(t)
	udpEcho := startUDPEcho(t)

	// --- lulutls server (engine): relay each admitted stream to its target ---
	h := func(user string, network byte, addr string, remote net.Addr, st io.ReadWriteCloser) {
		defer st.Close()
		switch network {
		case engine.NetTCP:
			up, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer up.Close()
			go io.Copy(up, st)
			io.Copy(st, up)
		case engine.NetUDP:
			uc, err := net.Dial("udp", addr)
			if err != nil {
				return
			}
			defer uc.Close()
			go func() { // st (framed) -> udp
				var hdr [2]byte
				for {
					if _, e := io.ReadFull(st, hdr[:]); e != nil {
						return
					}
					b := make([]byte, binary.BigEndian.Uint16(hdr[:]))
					if _, e := io.ReadFull(st, b); e != nil {
						return
					}
					uc.Write(b)
				}
			}()
			buf := make([]byte, 65535) // udp -> st (framed)
			for {
				n, e := uc.Read(buf)
				if e != nil {
					return
				}
				out := make([]byte, 2+n)
				binary.BigEndian.PutUint16(out[:2], uint16(n))
				copy(out[2:], buf[:n])
				st.Write(out)
			}
		}
	}

	srv, err := engine.New(engine.Config{
		Lane:    "ws",
		Listen:  "127.0.0.1:0",
		SNI:     sni,
		NodeKey: nodeKey,
		Profile: "balanced",
	}, h)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	srv.SetUsers([]engine.User{{Name: uuid, PSK: psk}})
	if err := srv.Start(); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// --- the real mihomo LuluTLS outbound ---
	proxy, err := NewLuluTLS(LuluTLSOption{
		Name:           "lulu-it",
		Server:         host,
		Port:           port,
		PSK:            hex.EncodeToString(psk),
		NodeKey:        string(nodeKey),
		Lane:           "ws",
		SNI:            sni,
		Shape:          "balanced",
		SkipCertVerify: true,
		UDP:            true,
	})
	if err != nil {
		t.Fatalf("NewLuluTLS: %v", err)
	}
	defer proxy.Close()

	t.Run("TCP", func(t *testing.T) {
		eHost, ePortStr, _ := net.SplitHostPort(tcpEcho)
		ePort, _ := strconv.Atoi(ePortStr)
		md := &C.Metadata{NetWork: C.TCP, Host: eHost, DstPort: uint16(ePort)}

		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		c, err := proxy.DialContext(ctx, md)
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		defer c.Close()

		msg := []byte("lulutls-adapter-tcp-roundtrip")
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(got) != string(msg) {
			t.Fatalf("tcp echo mismatch: got %q want %q", got, msg)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		eAddr := netip.MustParseAddrPort(udpEcho)
		md := &C.Metadata{NetWork: C.UDP, DstIP: eAddr.Addr(), DstPort: eAddr.Port()}

		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		pc, err := proxy.ListenPacketContext(ctx, md)
		if err != nil {
			t.Fatalf("ListenPacketContext: %v", err)
		}
		defer pc.Close()

		msg := []byte("lulutls-adapter-udp-roundtrip")
		if _, err := pc.WriteTo(msg, net.UDPAddrFromAddrPort(eAddr)); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 65535)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Fatalf("udp echo mismatch: got %q want %q", buf[:n], msg)
		}
	})
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:n], addr)
		}
	}()
	return uc.LocalAddr().String()
}
