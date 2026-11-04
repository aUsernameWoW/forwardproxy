package forwardproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type uotTestDatagram struct {
	payload []byte
	addr    net.Addr
}

// uotTestPacketConn stands in for the outbound UDP socket.
type uotTestPacketConn struct {
	in     chan uotTestDatagram // datagrams "received" from the internet
	out    chan uotTestDatagram // datagrams the UoT server sent
	closed chan struct{}
}

func newUoTTestPacketConn() *uotTestPacketConn {
	return &uotTestPacketConn{
		in:     make(chan uotTestDatagram, 4),
		out:    make(chan uotTestDatagram, 4),
		closed: make(chan struct{}),
	}
}

func (p *uotTestPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case d := <-p.in:
		return copy(b, d.payload), d.addr, nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	}
}

func (p *uotTestPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.out <- uotTestDatagram{payload: append([]byte(nil), b...), addr: addr}
	return len(b), nil
}

func (p *uotTestPacketConn) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}
func (p *uotTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (p *uotTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (p *uotTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *uotTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func uotTestFrame(t *testing.T, dest *M.Socksaddr, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if dest != nil {
		if err := uot.AddrParser.WriteAddrPort(&b, *dest); err != nil {
			t.Fatal(err)
		}
	}
	_ = binary.Write(&b, binary.BigEndian, uint16(len(payload)))
	b.Write(payload)
	return b.Bytes()
}

func uotTestRecv(t *testing.T, ch <-chan uotTestDatagram) uotTestDatagram {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for datagram")
		return uotTestDatagram{}
	}
}

func TestUoTResponseIsOneRead(t *testing.T) {
	for _, src := range []*net.UDPAddr{
		{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 53},
		{IP: net.IPv4(1, 2, 3, 4), Port: 53}, // 4-in-6 form, as from a dual-stack socket
		{IP: net.ParseIP("2001:db8::1"), Port: 443},
	} {
		pc := newUoTTestPacketConn()
		c := newUoTServerConn(pc, uot.LegacyVersion)
		payload := bytes.Repeat([]byte{7}, 100)
		pc.in <- uotTestDatagram{payload: payload, addr: src}

		buf := make([]byte, 65536)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		srcAddr := M.SocksaddrFromNet(src)
		want := uotTestFrame(t, &srcAddr, payload)
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("src %v: got frame %x, want %x", src, buf[:n], want)
		}
		c.Close()
	}
}

func TestUoTResponseSmallReadBuffer(t *testing.T) {
	pc := newUoTTestPacketConn()
	c := newUoTServerConn(pc, uot.LegacyVersion)
	src := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	pc.in <- uotTestDatagram{payload: []byte("first"), addr: src}
	pc.in <- uotTestDatagram{payload: []byte("second"), addr: src}

	srcAddr := M.SocksaddrFromNet(src)
	want := append(uotTestFrame(t, &srcAddr, []byte("first")), uotTestFrame(t, &srcAddr, []byte("second"))...)
	got := make([]byte, len(want))
	small := make([]byte, 3)
	for off := 0; off < len(want); {
		n, err := c.Read(small)
		if err != nil {
			t.Fatal(err)
		}
		off += copy(got[off:], small[:n])
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
	c.Close()
}

func TestUoTV2ConnectResolvesOnce(t *testing.T) {
	var lookups atomic.Int32
	orig := uotResolveUDPAddr
	uotResolveUDPAddr = func(network, address string) (*net.UDPAddr, error) {
		lookups.Add(1)
		if address != "dns.example:53" {
			t.Errorf("unexpected lookup %q", address)
		}
		return &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8).To4(), Port: 53}, nil
	}
	defer func() { uotResolveUDPAddr = orig }()

	pc := newUoTTestPacketConn()
	c := newUoTServerConn(pc, uot.Version)
	go func() {
		_ = uot.WriteRequest(c, uot.Request{IsConnect: true, Destination: M.ParseSocksaddrHostPort("dns.example", 53)})
		for i := 0; i < 3; i++ {
			_, _ = c.Write(uotTestFrame(t, nil, []byte{byte(i)}))
		}
	}()
	for i := 0; i < 3; i++ {
		d := uotTestRecv(t, pc.out)
		if d.addr.String() != "5.6.7.8:53" || !bytes.Equal(d.payload, []byte{byte(i)}) {
			t.Errorf("datagram %d: got %v %x", i, d.addr, d.payload)
		}
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("resolved %d times, want 1", n)
	}

	// Connect-mode responses carry no address.
	pc.in <- uotTestDatagram{payload: []byte("resp"), addr: &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8).To4(), Port: 53}}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := uotTestFrame(t, nil, []byte("resp")); !bytes.Equal(buf[:n], want) {
		t.Errorf("got %x, want %x", buf[:n], want)
	}
	c.Close()
}

func TestUoTV2ConnectUnresolvableCloses(t *testing.T) {
	orig := uotResolveUDPAddr
	uotResolveUDPAddr = func(string, string) (*net.UDPAddr, error) { return nil, errors.New("nxdomain") }
	defer func() { uotResolveUDPAddr = orig }()

	pc := newUoTTestPacketConn()
	c := newUoTServerConn(pc, uot.Version)
	go func() {
		_ = uot.WriteRequest(c, uot.Request{IsConnect: true, Destination: M.ParseSocksaddrHostPort("nx.example", 53)})
	}()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 64))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read succeeded on a session whose destination did not resolve")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session was not closed")
	}
}

func TestUoTUnresolvableFrameKeepsStreamInSync(t *testing.T) {
	orig := uotResolveUDPAddr
	uotResolveUDPAddr = func(string, string) (*net.UDPAddr, error) { return nil, errors.New("nxdomain") }
	defer func() { uotResolveUDPAddr = orig }()

	pc := newUoTTestPacketConn()
	c := newUoTServerConn(pc, uot.LegacyVersion)
	bad := M.ParseSocksaddrHostPort("nx.example", 53)
	good := M.ParseSocksaddrHostPort("8.8.8.8", 53)
	go func() {
		_, _ = c.Write(uotTestFrame(t, &bad, []byte{0x01, 0x05, 9, 9, 0, 3}))
		_, _ = c.Write(uotTestFrame(t, &good, []byte("ok")))
	}()
	d := uotTestRecv(t, pc.out)
	if d.addr.String() != "8.8.8.8:53" || string(d.payload) != "ok" {
		t.Errorf("got %v %q, want 8.8.8.8:53 \"ok\"", d.addr, d.payload)
	}
	c.Close()
}

func TestUoTCloseUnblocksRead(t *testing.T) {
	pc := newUoTTestPacketConn()
	c := newUoTServerConn(pc, uot.Version)
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 64))
		done <- err
	}()
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("Read returned %v after Close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read still blocked after Close")
	}
}
