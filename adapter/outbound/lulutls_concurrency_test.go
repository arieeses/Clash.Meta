package outbound

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestLuluPacketConnConcurrentReadFrom reproduces the crash path: pion
// (ICE/DTLS/SCTP) issues concurrent ReadFrom on the same net.PacketConn.
// luluPacketConn.ReadFrom does a non-atomic 2-step framed read (length prefix,
// then payload). Without the rMu serialization the two steps from different
// goroutines interleave, desync the framing, and hand a bogus length / mixed
// payload to the caller -> memory corruption. Each frame here is filled with a
// single repeated byte so any desync shows up as a mixed-content payload.
// Run with -race to also catch the raw data race on the underlying conn.
func TestLuluPacketConnConcurrentReadFrom(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	pc := &luluPacketConn{Conn: cli, target: dummyAddr{}}

	const frames = 4000
	// Producer: write well-formed frames of varying length, each a run of one byte,
	// then close the write side so idle readers unblock with EOF.
	go func() {
		for i := 0; i < frames; i++ {
			n := 1 + (i*37)%1400 // 1..1400 bytes, varied
			v := byte(i)
			payload := make([]byte, n)
			for j := range payload {
				payload[j] = v
			}
			buf := make([]byte, 2+n)
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			copy(buf[2:], payload)
			if _, err := srv.Write(buf); err != nil {
				return
			}
		}
		srv.Close()
	}()

	var got int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	const readers = 8

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return // EOF once producer closed and all frames drained
				}
				if n == 0 {
					t.Errorf("read zero-length frame (framing desync)")
					return
				}
				// Every byte of a correctly-framed payload must equal the first byte.
				first := buf[0]
				for k := 1; k < n; k++ {
					if buf[k] != first {
						t.Errorf("framing desync: byte %d=%d != first=%d (len=%d)", k, buf[k], first, n)
						return
					}
				}
				mu.Lock()
				got++
				mu.Unlock()
			}
		}()
	}

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout: readers did not drain all frames (possible deadlock/desync)")
	}

	mu.Lock()
	defer mu.Unlock()
	if got != frames {
		t.Fatalf("read %d frames, want %d (desync/loss)", got, frames)
	}
}

// TestLuluPacketConnConcurrentWriteTo verifies concurrent WriteTo keeps each
// framed datagram atomic on the wire (wMu). A single draining goroutine on the
// peer parses frames back and asserts each payload is a clean single-byte run.
func TestLuluPacketConnConcurrentWriteTo(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	pc := &luluPacketConn{Conn: cli, target: dummyAddr{}}

	const writers = 8
	const perWriter = 500
	total := writers * perWriter

	// Drain + validate frames on the peer end.
	errCh := make(chan error, 1)
	go func() {
		var hdr [2]byte
		for i := 0; i < total; i++ {
			if _, err := io.ReadFull(srv, hdr[:]); err != nil {
				errCh <- err
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			payload := make([]byte, n)
			if _, err := io.ReadFull(srv, payload); err != nil {
				errCh <- err
				return
			}
			if n == 0 {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			first := payload[0]
			for k := 1; k < n; k++ {
				if payload[k] != first {
					t.Errorf("write framing desync at frame %d: byte %d=%d != %d", i, k, payload[k], first)
					errCh <- io.ErrUnexpectedEOF
					return
				}
			}
		}
		errCh <- nil
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				n := 1 + ((w*7+i*13)%900)
				v := byte(w*31 + i)
				p := make([]byte, n)
				for j := range p {
					p[j] = v
				}
				if _, err := pc.WriteTo(p, dummyAddr{}); err != nil {
					return
				}
			}
		}(w)
	}
	wg.Wait()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("drain failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout draining written frames")
	}
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "udp" }
func (dummyAddr) String() string  { return "0.0.0.0:0" }
