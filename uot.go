package forwardproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

// uotMaxHeaderLen is the largest per-frame header the server ever writes:
// an IPv6 address (1 family byte + 16) + 2 port bytes + 2 length bytes.
// Response sources come from ReadFrom and are always IPs, never FQDNs.
const uotMaxHeaderLen = 1 + 16 + 2 + 2

// uotServerConn is the server side of sing's UDP-over-TCP (v1 and v2),
// replacing uot.NewServerConn. Differences from sing's implementation:
//   - Each response datagram is handed to Read as one contiguous frame
//     (address, length and payload together). sing writes the three parts
//     through an io.Pipe separately, which surfaces as three Reads and so
//     three Write+Flush calls (three tiny DATA frames) per datagram, and
//     spends the stream's first few padded writes on 2- and 7-byte pieces.
//   - In v2 connect mode the fixed destination is resolved once, not once
//     per datagram.
type uotServerConn struct {
	net.PacketConn
	version int

	// Client -> server: Write feeds a pipe that loopInput parses.
	inputReader *io.PipeReader
	inputWriter *io.PipeWriter

	// Set by loopInput from the v2 request before the first datagram is
	// sent, so Read only consults them after ready is closed.
	isConnect bool
	ready     chan struct{}

	// Server -> client: one encoded frame, drained by Read.
	readBuf []byte
	pending []byte

	closeOnce sync.Once
}

func newUoTServerConn(pc net.PacketConn, version int) net.Conn {
	c := &uotServerConn{
		PacketConn: pc,
		version:    version,
		ready:      make(chan struct{}),
		readBuf:    make([]byte, uotMaxHeaderLen+65535),
	}
	c.inputReader, c.inputWriter = io.Pipe()
	go c.loopInput()
	return c
}

func (c *uotServerConn) loopInput() {
	defer c.Close()
	var connectDest *net.UDPAddr
	if c.version == uot.Version {
		request, err := uot.ReadRequest(c.inputReader)
		if err != nil {
			close(c.ready)
			return
		}
		c.isConnect = request.IsConnect
		if c.isConnect {
			connectDest, err = resolveUoTDestination(request.Destination)
			if err != nil {
				close(c.ready)
				return
			}
		}
	}
	close(c.ready)

	payload := make([]byte, 65535)
	for {
		dest := connectDest
		if !c.isConnect {
			addr, err := uot.AddrParser.ReadAddrPort(c.inputReader)
			if err != nil {
				return
			}
			// Unresolvable destinations drop only their own datagram; the
			// length and payload below are still consumed to stay in frame.
			dest, _ = resolveUoTDestination(addr)
		}
		var length uint16
		if err := binary.Read(c.inputReader, binary.BigEndian, &length); err != nil {
			return
		}
		if _, err := io.ReadFull(c.inputReader, payload[:length]); err != nil {
			return
		}
		if dest == nil {
			continue
		}
		if _, err := c.WriteTo(payload[:length], dest); err != nil {
			return
		}
	}
}

// uotResolveUDPAddr is swapped out by tests.
var uotResolveUDPAddr = net.ResolveUDPAddr

// resolveUoTDestination turns a frame destination into a UDP address,
// resolving FQDNs the same way sing's server does.
func resolveUoTDestination(addr M.Socksaddr) (*net.UDPAddr, error) {
	if addr.IsIP() {
		return addr.UDPAddr(), nil
	}
	if addr.Fqdn == "" {
		return nil, errors.New("uot: empty destination")
	}
	return uotResolveUDPAddr("udp", addr.String())
}

func (c *uotServerConn) Write(b []byte) (int, error) {
	return c.inputWriter.Write(b)
}

func (c *uotServerConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// readFrame receives one datagram and encodes it, header included, into
// readBuf. The payload is read at a fixed offset and the header is written
// immediately in front of it, so the frame needs no extra copy.
func (c *uotServerConn) readFrame() error {
	<-c.ready
	n, addr, err := c.ReadFrom(c.readBuf[uotMaxHeaderLen:])
	if err != nil {
		return err
	}
	var header [uotMaxHeaderLen]byte
	hb := buf.With(header[:])
	if !c.isConnect {
		src := M.SocksaddrFromNet(addr)
		if !src.IsIP() {
			return errors.New("uot: response source is not an IP")
		}
		if err := uot.AddrParser.WriteAddrPort(hb, src); err != nil {
			return err
		}
	}
	if err := binary.Write(hb, binary.BigEndian, uint16(n)); err != nil {
		return err
	}
	h := hb.Bytes()
	start := uotMaxHeaderLen - len(h)
	copy(c.readBuf[start:], h)
	c.pending = c.readBuf[start : uotMaxHeaderLen+n]
	return nil
}

func (c *uotServerConn) RemoteAddr() net.Addr {
	return M.Socksaddr{Fqdn: "pipe"}
}

func (c *uotServerConn) Close() error {
	c.closeOnce.Do(func() {
		c.inputReader.Close()
		c.inputWriter.Close()
		c.PacketConn.Close()
	})
	return nil
}
