package outbound

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	luluclient "lulutls/client"
)

// LuluTLS is a mihomo outbound for the lulutls multi-carrier anti-censorship
// protocol. It wraps lulutls/client.Dialer: one shared, re-dialable mux session
// per node, over which each proxied flow is a demultiplexed stream. The
// underlying transport to the node is dialed through mihomo's own dialer (so the
// socket is marked/bound and does not loop back through TUN).
type LuluTLS struct {
	*Base
	option *LuluTLSOption
	client *luluclient.Dialer
}

type LuluTLSOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	PSK            string `proxy:"psk"`                    // per-user pre-shared key, hex
	NodeKey        string `proxy:"node-key,omitempty"`     // node carrier key (lane C/E), raw string
	Lane           string `proxy:"lane,omitempty"`         // ws | lowent | borrow
	SNI            string `proxy:"sni,omitempty"`          // server name (TLS lanes)
	Path           string `proxy:"path,omitempty"`         // WS path / routing prefix
	Cipher         string `proxy:"cipher,omitempty"`       // aes | xchacha | chacha
	Shape          string `proxy:"shape,omitempty"`        // off | lite | balanced | paranoid
	Fingerprint    string `proxy:"fp,omitempty"`           // chrome | firefox (panel emits "fp")
	Codec          string `proxy:"lane-c-codec,omitempty"` // basen | arith (lane C)
	NoMux          bool   `proxy:"nomux,omitempty"`        // legacy: skip mux (= mux "off"); prefer Mux
	Mux            string `proxy:"mux,omitempty"`          // off | low | mid | high (mieru-style session pool)
	Window         int    `proxy:"window,omitempty"`       // per-stream recv window KiB (0 => adaptive); mux mode
	FrameSize      int    `proxy:"frame,omitempty"`        // send-side frame size KiB (0 => 16); larger = fewer syscalls
	Media          string `proxy:"media,omitempty"`        // lane G: audio (default) | video (higher bitrate)
	Cover          string `proxy:"cover,omitempty"`        // server-side cover origin; carried in the sub, unused by the client
	UDP            bool   `proxy:"udp,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
}

// DialContext implements C.ProxyAdapter.
func (l *LuluTLS) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := l.client.DialTCP(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", l.addr, err)
	}
	return NewConn(c, l), nil
}

// ListenPacketContext implements C.ProxyAdapter. UDP rides a UoT stream whose
// wire form is uint16-length-prefixed datagrams, bound to the one target.
func (l *LuluTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := l.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	target := metadata.UDPAddr()
	c, err := l.client.DialUDP(ctx, target.String())
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", l.addr, err)
	}
	pc := &luluPacketConn{Conn: c, target: target}
	return NewPacketConn(N.NewThreadSafePacketConn(pc), l), nil
}

// SupportUOT implements C.ProxyAdapter: lulutls carries UDP over a tunnelled
// stream (UoT), not a native UDP association.
func (l *LuluTLS) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter.
func (l *LuluTLS) ProxyInfo() C.ProxyInfo {
	info := l.Base.ProxyInfo()
	info.DialerProxy = l.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter.
func (l *LuluTLS) Close() error {
	if l.client != nil {
		return l.client.Close()
	}
	return nil
}

func NewLuluTLS(option LuluTLSOption) (*LuluTLS, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("lulutls %s: server is empty", option.Name)
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("lulutls %s: invalid port %d", option.Name, option.Port)
	}
	if option.PSK == "" {
		return nil, fmt.Errorf("lulutls %s: psk is empty", option.Name)
	}
	psk, err := hex.DecodeString(option.PSK)
	if err != nil {
		return nil, fmt.Errorf("lulutls %s: psk must be hex: %w", option.Name, err)
	}
	// node-key is used as raw string bytes on both ends (never hex-decoded),
	// matching the panel / engine contract.
	var nodeKey []byte
	if option.NodeKey != "" {
		nodeKey = []byte(option.NodeKey)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &LuluTLS{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.LuluTLS,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	cfg := luluclient.Config{
		Server:      addr,
		SNI:         option.SNI,
		Path:        option.Path,
		PSK:         psk,
		NodeKey:     nodeKey,
		Lane:        option.Lane,
		Cipher:      option.Cipher,
		Shape:       option.Shape,
		Fingerprint: option.Fingerprint,
		Arith:       option.Codec == "arith",
		NoMux:       option.NoMux,
		Mux:          option.Mux,
		Window:       option.Window,
		FrameSize:    option.FrameSize,
		MediaProfile: option.Media,
		Insecure:    option.SkipCertVerify,
		// Dial the node through mihomo's dialer so the socket is marked/bound
		// (escapes the TUN capture loop) and honours interface / routing-mark.
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return outbound.dialer.DialContext(ctx, network, address)
		},
		// UDP lanes (quic/webrtc) get their socket from mihomo's dialer too, so
		// it carries DefaultSocketHook (VpnService.protect) and is excluded from
		// the TUN — otherwise quic-go/pion open their own raw socket and loop.
		ListenPacket: func(ctx context.Context) (net.PacketConn, error) {
			rAddrPort, _ := netip.ParseAddrPort(addr) // zero if server is a domain; protect still applies
			return outbound.dialer.ListenPacket(ctx, "udp", "", rAddrPort)
		},
	}
	client, err := luluclient.NewDialer(cfg)
	if err != nil {
		return nil, fmt.Errorf("lulutls %s: %w", option.Name, err)
	}
	outbound.client = client
	return outbound, nil
}

// luluPacketConn adapts a lulutls UoT stream (uint16-length-prefixed datagrams,
// one target per stream) to net.PacketConn, bound to that single target.
type luluPacketConn struct {
	net.Conn
	target net.Addr
	rMu    sync.Mutex // serializes the 2-step framed read (hdr + payload) across concurrent ReadFrom
	wMu    sync.Mutex // serializes the framed write across concurrent WriteTo
}

func (pc *luluPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > 0xffff {
		return 0, fmt.Errorf("lulutls: udp payload too large (%d)", len(p))
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	// net.PacketConn allows concurrent WriteTo; keep each framed datagram
	// (2-byte length prefix + payload) atomic on the wire so frames never interleave.
	pc.wMu.Lock()
	_, err := pc.Conn.Write(buf)
	pc.wMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *luluPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// net.PacketConn allows concurrent ReadFrom (pion ICE/DTLS/SCTP do this).
	// The read is two non-atomic steps (length prefix, then payload); without
	// serialization concurrent readers desync the framing and hand garbage/oversized
	// lengths to the caller, which corrupts memory. Hold rMu for the whole frame.
	pc.rMu.Lock()
	defer pc.rMu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(pc.Conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(pc.Conn, buf); err != nil {
		return 0, nil, err
	}
	return copy(p, buf), pc.target, nil
}
