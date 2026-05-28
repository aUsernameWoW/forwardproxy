// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// RFC 9298 — Proxying UDP in HTTP (CONNECT-UDP / MASQUE).
//
// The core protocol implementation here is adapted from commit
// f92c1a3a39c0be4c7c1e007abf1a2ee8e0b2b1df ("add UDP in HTTP"), which was
// reverted from the naive branch in favour of sing UoT. This file restores
// that work as a standalone handler so it can coexist with UoT.

package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/zap"
)

const (
	RequestProtocol = "connect-udp"

	ConnectUDPBindHeader     = "Connect-Udp-Bind"
	ProxyPublicAddressHeader = "Proxy-Public-Address"

	CompressionAssignValue = 0x1C0FE323
	CompressionCloseValue  = 0x1C0FE324
)

var (
	CapsuleProtocolHeaderValue string
	ConnectUDPBindHeaderValue  string
)

func init() {
	str, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	CapsuleProtocolHeaderValue = str
	ConnectUDPBindHeaderValue = str
}

type Payload interface {
	Len() uint64
	Parse([]byte) error
	Send(io.Writer) error
}

type Datagram struct {
	Type    uint64
	Length  uint64
	Payload Payload
}

func (data *Datagram) Receive(r io.Reader) error {
	return data.ReceiveBuffer(r, make([]byte, 1024*32))
}

func (data *Datagram) ReceiveBuffer(r io.Reader, b []byte) error {
	err := error(nil)

	rr := quicvarint.NewReader(r)
	data.Type, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram type error: %w", err)
	}

	data.Length, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram length error: %w", err)
	}

	// data.Length is an attacker-controlled varint (up to 2^62-1). Reject
	// anything larger than the caller's buffer before slicing, otherwise
	// b[:data.Length] panics out of bounds and crashes the whole process.
	if data.Length > uint64(len(b)) {
		return fmt.Errorf("receive datagram payload error: length %d exceeds buffer size %d", data.Length, len(b))
	}

	bb := b[:data.Length]
	_, err = io.ReadFull(r, bb)
	if err != nil {
		return fmt.Errorf("receive datagram payload error: %w", err)
	}

	data.Payload = &BytePayload{Payload: bb}

	return nil
}

func (data *Datagram) Send(w io.Writer) error {
	bb := quicvarint.Append(quicvarint.Append(make([]byte, 0, 16), data.Type), data.Length)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send type, length error: %w", err)
	}

	err = data.Payload.Send(w)
	if err != nil {
		return fmt.Errorf("send UDP payload error: %w", err)
	}

	return nil
}

type BytePayload struct {
	Payload []byte
}

func (data *BytePayload) Send(w io.Writer) error {
	_, err := w.Write(data.Payload)
	return err
}

func (data *BytePayload) Len() uint64 {
	return uint64(len(data.Payload))
}

func (data *BytePayload) Parse(b []byte) error {
	data.Payload = b
	return nil
}

type CompressedPayload struct {
	ContextID uint64
	Payload   []byte
}

func (data *CompressedPayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *CompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	data.ContextID = id
	data.Payload = b[nr:]
	return nil
}

func (data *CompressedPayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID)) + uint64(len(data.Payload))
}

type UncompressedPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
	Payload   []byte
}

func (data *UncompressedPayload) Send(w io.Writer) error {
	bb := append(append(append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion)),
		data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send uncompressed payload header error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *UncompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	if nr >= len(b) {
		return fmt.Errorf("uncompressed payload truncated: missing IP version")
	}

	switch b[nr] { // IPVersion
	case 4:
		if len(b) < nr+7 {
			return fmt.Errorf("uncompressed payload truncated: need %d bytes for IPv4 address+port, have %d", nr+7, len(b))
		}
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
		data.Payload = b[nr+7:]
	case 6:
		if len(b) < nr+19 {
			return fmt.Errorf("uncompressed payload truncated: need %d bytes for IPv6 address+port, have %d", nr+19, len(b))
		}
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
		data.Payload = b[nr+19:]
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *UncompressedPayload) Len() uint64 {
	switch data.IPVersion {
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2 + uint64(len(data.Payload))
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2 + uint64(len(data.Payload))
	}
	return 0
}

type CompressionAssignPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
}

func (data *CompressionAssignPayload) Send(w io.Writer) error {
	bb := append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion))
	if data.IPVersion != 0 {
		bb = append(append(bb, data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	}

	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send compression assign payload header error: %w", err)
	}

	return nil
}

func (data *CompressionAssignPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	if nr >= len(b) {
		return fmt.Errorf("compression assign payload truncated: missing IP version")
	}

	switch b[nr] { // IPVersion
	case 0:
		data.IPVersion = 0
	case 4:
		if len(b) < nr+7 {
			return fmt.Errorf("compression assign payload truncated: need %d bytes for IPv4 address+port, have %d", nr+7, len(b))
		}
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
	case 6:
		if len(b) < nr+19 {
			return fmt.Errorf("compression assign payload truncated: need %d bytes for IPv6 address+port, have %d", nr+19, len(b))
		}
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *CompressionAssignPayload) Len() uint64 {
	switch data.IPVersion {
	case 0:
		// context id is 2
		return 1 + 1
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2
	}
	return 0
}

type CompressionClosePayload struct {
	ContextID uint64
}

func (data *CompressionClosePayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}
	return nil
}

func (data *CompressionClosePayload) Parse(b []byte) error {
	var err error
	data.ContextID, _, err = quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("parse context id error: %v", err)
	}
	return nil
}

func (data *CompressionClosePayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID))
}

type PacketConn struct {
	DatagramSender
	Conn       io.Reader
	ContextID  uint64
	ContextMap struct {
		sync.RWMutex
		Map map[uint64]netip.AddrPort
	}
	AddrMap struct {
		sync.RWMutex
		Map map[netip.AddrPort]uint64
	}

	firewall atomic.Bool
}

func newPacketConn(rw io.ReadWriter) *PacketConn {
	nm := PacketConn{
		DatagramSender: DatagramSender{
			w: rw,
		},
		Conn:      rw,
		ContextID: 1,
	}
	nm.ContextMap.Map = map[uint64]netip.AddrPort{}
	nm.AddrMap.Map = map[netip.AddrPort]uint64{}
	return &nm
}

func (nm *PacketConn) GetAddr(id uint64) (netip.AddrPort, bool) {
	nm.ContextMap.RLock()
	addr, ok := nm.ContextMap.Map[id]
	nm.ContextMap.RUnlock()
	return addr, ok
}

func (nm *PacketConn) GetContextID(addr netip.AddrPort) (uint64, bool) {
	nm.AddrMap.RLock()
	id, ok := nm.AddrMap.Map[addr]
	nm.AddrMap.RUnlock()
	return id, ok
}

func (nm *PacketConn) Add(id uint64, addr netip.AddrPort) {
	nm.ContextMap.Lock()
	nm.AddrMap.Lock()
	nm.ContextMap.Map[id] = addr
	nm.AddrMap.Map[addr] = id
	nm.AddrMap.Unlock()
	nm.ContextMap.Unlock()
}

func (nm *PacketConn) Del(id uint64) {
	nm.ContextMap.Lock()
	addr, ok := nm.ContextMap.Map[id]
	delete(nm.ContextMap.Map, id)
	if ok {
		nm.AddrMap.Lock()
		delete(nm.AddrMap.Map, addr)
		nm.AddrMap.Unlock()
	}
	nm.ContextMap.Unlock()
}

func (pc *PacketConn) WritePacket(b []byte, addr netip.AddrPort) error {
	id, ok := pc.GetContextID(addr)
	if !ok {
		if pc.Firewall() {
			return nil
		}

		pc.ContextID += 2 // odd context id for server side compression assign
		id = pc.ContextID

		// send compression assign to utlize compressed payload
		data := Datagram{
			Type: CompressionAssignValue,
		}
		pl := CompressionAssignPayload{}
		pl.ContextID = id
		if naddr := addr.Addr(); naddr.Is4() {
			pl.IPVersion = 4
			pl.Addr = naddr
		} else {
			pl.IPVersion = 6
			pl.Addr = naddr
		}
		pl.Port = addr.Port()
		data.Length = pl.Len()
		data.Payload = &pl

		err := pc.SendDatagram(data)
		if err != nil {
			return err
		}

		pc.Add(id, netip.AddrPortFrom(pl.Addr, pl.Port))
	}

	data := Datagram{
		Type: 0,
	}
	pl := &CompressedPayload{
		ContextID: id,
		Payload:   b,
	}
	data.Length = pl.Len()
	data.Payload = pl

	return pc.SendDatagram(data)
}

func (nm *PacketConn) ReadPacket(b []byte) ([]byte, netip.AddrPort, error) {
	data := Datagram{}

	for {
		err := data.ReceiveBuffer(nm.Conn, b)
		if err != nil {
			return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
		}

		bb := (data.Payload.(*BytePayload)).Payload
		switch data.Type {
		case 0:
			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}

			if id == 2 {
				if nm.Firewall() {
					// ignore all packets with context id 2 when assign-close is set
					continue
				}
				// bb is an attacker-sized payload; validate length before
				// indexing the inline address/port so a short frame can't
				// panic the read goroutine and crash the process.
				if len(bb) < 2 {
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("id-2 datagram truncated: missing IP version")
				}
				switch bb[1] {
				case 4:
					if len(bb) < 8 {
						return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("id-2 datagram truncated: need 8 bytes for IPv4 address+port, have %d", len(bb))
					}
					return bb[8:], netip.AddrPortFrom(netip.AddrFrom4(
						[4]byte{bb[2], bb[3], bb[4], bb[5]}), uint16(bb[6])<<8|uint16(bb[7])), nil
				case 6:
					if len(bb) < 20 {
						return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("id-2 datagram truncated: need 20 bytes for IPv6 address+port, have %d", len(bb))
					}
					return bb[20:], netip.AddrPortFrom(netip.AddrFrom16(
						[16]byte{bb[2], bb[3], bb[4], bb[5],
							bb[6], bb[7], bb[8], bb[9],
							bb[10], bb[11], bb[12], bb[13],
							bb[14], bb[15], bb[16], bb[17]}), uint16(bb[18])<<8|uint16(bb[19])), nil
				default:
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("ip version error: %v", bb[1])
				}
			}

			addr, ok := nm.GetAddr(id)
			if ok {
				return bb[nr:], addr, nil
			}
		case CompressionAssignValue:
			data := Datagram{
				Type: CompressionAssignValue,
			}
			pl := CompressionAssignPayload{}
			if err := pl.Parse(bb); err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}
			data.Length = pl.Len()
			data.Payload = &pl

			// even for client side, odd for server side; ignore all odd ids
			if pl.ContextID&1 == 0 {
				switch pl.IPVersion {
				case 0:
					if pl.ContextID != 2 {
						// use 2 for default uncompressed context id
						continue
					}

					nm.SetFirewall(false)
				case 4:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				case 6:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				default:
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("ip version error: %v", bb[1])
				}

				err := nm.SendDatagram(data)
				if err != nil {
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
				}
			}
		case CompressionCloseValue:
			data := Datagram{
				Type: CompressionCloseValue,
			}
			pl := CompressionClosePayload{}
			err = pl.Parse(bb)
			if err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}
			data.Length = pl.Len()
			data.Payload = &pl

			if pl.ContextID&1 == 0 {
				if pl.ContextID == 2 {
					nm.SetFirewall(true)
				} else {
					nm.Del(pl.ContextID)
				}

				err = nm.SendDatagram(data)
				if err != nil {
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
				}
			}
		default:
			continue
		}
	}
}

func (nm *PacketConn) Firewall() bool {
	return nm.firewall.Load()
}

func (nm *PacketConn) SetFirewall(ok bool) {
	nm.firewall.Store(ok)
}

type Request string

type RequestMatcher struct {
	source       string
	tokens       []string
	patternRegex *regexp.Regexp
}

func (rm *RequestMatcher) Create(source string) error {
	const tempToken = "__TMPTKN__"

	delimiters := []rune{'{', '}'}

	tokenRegex := regexp.MustCompile(string(delimiters[0]) + "([^" + string(delimiters) + "\\t\\r\\n]+)" + string(delimiters[1]))
	tokenMatches := tokenRegex.FindAllStringSubmatch(source, -1)
	tokens := make([]string, len(tokenMatches))
	for i, v := range tokenMatches {
		tokens[i] = v[1]
	}

	// substitute before escaping so capture groups survive QuoteMeta
	substitutedTemplate := tokenRegex.ReplaceAllString(source, tempToken)
	escapedSubstitutedTemplate := regexp.QuoteMeta(substitutedTemplate)
	escapedTemplate := strings.ReplaceAll(escapedSubstitutedTemplate, tempToken, "(.+)")
	patternRegex, err := regexp.Compile(escapedTemplate)
	if err != nil {
		return fmt.Errorf("error when constructing regex: %v", err)
	}

	rm.source = source
	rm.tokens = tokens
	rm.patternRegex = patternRegex
	return nil
}

func (rm RequestMatcher) Extract(input string) (map[string]string, error) {
	var ErrNoMatch = errors.New("unable to match")

	matches := rm.patternRegex.FindStringSubmatch(input)
	if len(matches) != len(rm.tokens)+1 {
		return nil, ErrNoMatch
	}

	result := make(map[string]string)
	for i, v := range rm.tokens {
		result[v] = matches[i+1]
	}

	return result, nil
}

type DatagramSender struct {
	sync.Mutex
	w io.Writer
}

func (ds *DatagramSender) SendDatagram(data Datagram) error {
	ds.Lock()
	err := data.Send(ds.w)
	ds.Unlock()
	return err
}

type udpProxyServer struct {
	*zap.Logger
	Matcher RequestMatcher
}

func newUDPProxyServer(uri string, lg *zap.Logger) (udpProxyServer, error) {
	srv := udpProxyServer{Logger: lg}
	if uri == "" {
		// CONNECT https://{host}/.well-known/masque/udp/{target_host}/{target_port}/
		// GET /.well-known/masque/udp/{target_host}/{target_port}/
		uri = "https://{host}/.well-known/masque/udp/{target_host}/{target_port}/"
	}
	err := srv.Matcher.Create(uri)
	if err != nil {
		return srv, fmt.Errorf("parse uri template error: %w", err)
	}
	return srv, err
}

// allowed, when non-nil, gates each per-packet destination in bind mode; nil
// allows all (used by the fixed-target path, which is ACL-checked before dial,
// and by tests).
func (srv udpProxyServer) HandleStream(c io.ReadWriter, req Request, rc *net.UDPConn, allowed func(netip.AddrPort) bool) error {
	if req == "*" {
		return srv.HandleStreamBind(c, req, rc, allowed)
	}

	done := make(chan struct{})

	go func() {
		b := make([]byte, 2048)
		for {
			data := Datagram{}
			err := data.ReceiveBuffer(c, b)
			if err != nil {
				break
			}

			if data.Type != 0 {
				continue
			}

			pl := &CompressedPayload{}
			err = pl.Parse((data.Payload.(*BytePayload)).Payload)
			if err != nil {
				break
			}

			if pl.ContextID != 0 {
				continue
			}

			_, err = rc.Write(pl.Payload)
			if err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	b := make([]byte, 2048)
	for {
		nr, err := rc.Read(b)
		if err != nil {
			break
		}

		data := Datagram{
			Type: 0,
		}
		pl := &CompressedPayload{
			ContextID: 0,
			Payload:   b[:nr],
		}

		// data.Length = quicvarint.Len(0) + uint64(nr)
		data.Length = 1 + uint64(nr)
		data.Payload = pl

		err = data.Send(c)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

func (srv udpProxyServer) HandleStreamBind(c io.ReadWriter, req Request, rc *net.UDPConn, allowed func(netip.AddrPort) bool) error {
	pc := newPacketConn(c)

	done := make(chan struct{})

	go func() {
		bb := make([]byte, 2048)
		for {
			pkt, addr, err := pc.ReadPacket(bb)
			if err != nil {
				break
			}

			// In bind mode the client picks the destination of every packet,
			// so each one must pass the ACL/port allowlist. Drop disallowed
			// destinations rather than killing the session.
			if allowed != nil && !allowed(addr) {
				continue
			}

			_, err = rc.WriteToUDPAddrPort(pkt, addr)
			if err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	bb := make([]byte, 2048)
	for {
		nr, addr, err := rc.ReadFromUDPAddrPort(bb)
		if err != nil {
			break
		}

		if addr.Addr().Is4In6() {
			addr = netip.AddrPortFrom(netip.AddrFrom4(addr.Addr().As4()), addr.Port())
		}

		err = pc.WritePacket(bb[:nr], addr)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

// http3UDPStream is the subset of *http3.Stream that HandlePacket uses.
// Defining it lets tests inject a mock without depending on quic-go's
// concrete Stream type (which changed from interface to struct in v0.54).
type http3UDPStream interface {
	io.Reader
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

func (srv udpProxyServer) HandlePacket(str http3UDPStream, req Request, rc *net.UDPConn) error {
	// https://github.com/quic-go/masque-go/issues/64
	if req == "*" {
		return srv.HandlePacketBind(str, req, rc)
	}

	// https://github.com/quic-go/masque-go/blob/master/proxy.go
	done := make(chan struct{})

	go func() {
		for {
			data, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				break
			}
			id, nr, err := quicvarint.Parse(data)
			if err != nil {
				break
			}
			if id != 0 {
				// only support proxying of UDP payloads
				continue
			}
			if _, err := rc.Write(data[nr:]); err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	go func() {
		b := make([]byte, 2048)
		for {
			nr, err := rc.Read(b[1:])
			if err != nil {
				break
			}

			// context id is always 0
			if err := str.SendDatagram(b[:nr+1]); err != nil {
				break
			}
		}

		done <- struct{}{}
	}()

	// discard all capsules sent on the request stream
	if err := func(str quicvarint.Reader) error {
		for {
			_, r, err := http3.ParseCapsule(str)
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
		}
	}(quicvarint.NewReader(str)); errors.Is(err, io.EOF) {
	}

	<-done
	<-done
	return nil
}

func (srv udpProxyServer) HandlePacketBind(str http3UDPStream, req Request, c *net.UDPConn) error {
	return fmt.Errorf("connect-udp-bind over http3 is not supported yet")
}

func (srv udpProxyServer) ParseRequest(r *http.Request) (Request, error) {
	switch r.ProtoMajor {
	case 1:
		if r.Method != http.MethodGet {
			return "", fmt.Errorf("expected GET request, got %s", r.Method)
		}
		if hdr := r.Header.Get("Connection"); hdr != "Upgrade" {
			return "", fmt.Errorf("unexpected Connection: %s", hdr)
		}
		if hdr := r.Header.Get("Upgrade"); hdr != RequestProtocol {
			return "", fmt.Errorf("unexpected Upgrade: %s", hdr)
		}
	case 2:
		// HTTP/2 extended CONNECT: :protocol pseudo-header surfaces as :protocol header
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if hdr := r.Header.Get(":protocol"); hdr != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", hdr)
		}
	case 3:
		// HTTP/3 extended CONNECT: quic-go exposes :protocol via r.Proto
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if r.Proto != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", r.Proto)
		}
	default:
		return "", fmt.Errorf("unexpected HTTP version: %v", r.ProtoMajor)
	}

	// Capsule-Protocol header is optional; validate when present
	if values, ok := r.Header[http3.CapsuleProtocolHeader]; ok {
		item, err := httpsfv.UnmarshalItem(values)
		if err != nil {
			return "", fmt.Errorf("invalid capsule header value: %s", values)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect capsule header value: %t", item.Value)
		}
	}

	var isUDPBind bool
	if values, ok := r.Header[ConnectUDPBindHeader]; ok {
		item, err := httpsfv.UnmarshalItem(values)
		if err != nil {
			return "", fmt.Errorf("invalid bind header value: %s", values)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect connect udp bind header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect connect udp bind header value: %t", item.Value)
		}
		isUDPBind = true
	}

	match, err := func() (map[string]string, error) {
		uri := *r.URL
		if uri.Scheme == "" {
			uri.Scheme = "https"
		}
		if uri.Host == "" {
			uri.Host = "in-place.com"
		}
		return srv.Matcher.Extract(uri.String())
	}()
	if err != nil {
		return "", fmt.Errorf("extract uri from %s error: %w", r.URL.String(), err)
	}

	targetHost := func(s string) string { return strings.ReplaceAll(s, "%3A", ":") }(match["target_host"])
	targetPortStr := match["target_port"]
	if targetHost == "" || targetPortStr == "" {
		return "", fmt.Errorf("expected target_host and target_port")
	}
	if targetHost == "*" && targetPortStr == "*" {
		if isUDPBind {
			return "*", nil
		}
		return "", fmt.Errorf("invalid Connect-UDP-Bind: %v", r.Header[ConnectUDPBindHeader])
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode target_port: %w", err)
	}
	return Request(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))), nil
}

// httpStream adapts a buffering HTTP ResponseWriter plus a request body into a
// single io.ReadWriter for HandleStream. It is used on the HTTP/2 connect-udp
// path, where the stdlib ResponseWriter implements neither http.Hijacker nor
// auto-flushing: reads come from the request body and each write is flushed so
// datagrams reach the client without waiting for the writer's own buffering.
type httpStream struct {
	r  io.Reader
	w  io.Writer
	rc *http.ResponseController
}

func newHTTPStream(w http.ResponseWriter, body io.Reader) *httpStream {
	return &httpStream{r: body, w: w, rc: http.NewResponseController(w)}
}

func (s *httpStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *httpStream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, s.rc.Flush()
}

// tryUDPoverHTTP handles an incoming connect-udp request per RFC 9298.
// Returns (true, err) when the request was claimed by the MASQUE path
// (regardless of outcome); (false, nil) when it should fall through to
// the normal proxy path. The claim boundary is a successful ParseRequest:
// once the request is recognised as connect-udp, every later failure is
// returned as (true, err) so the caller surfaces the status (e.g. 403/502)
// to the client instead of silently falling through.
func (h Handler) tryUDPoverHTTP(w http.ResponseWriter, r *http.Request) (bool, error) {
	// do not handle UDP over HTTP if upstream is set
	if h.upstream != nil {
		return false, nil
	}

	req, err := h.udpProxyServer.ParseRequest(r)
	if err != nil {
		// Not a connect-udp request (or one we can't parse): not claimed,
		// fall through to the normal proxy path per the contract above.
		return false, nil
	}

	var rconn *net.UDPConn
	if req == "*" {
		err := error(nil)
		rconn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError,
				fmt.Errorf("listen UDP connection error: %w", err))
		}
		defer rconn.Close()
	} else {
		ok, err := func(hostPort string) (bool, error) {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				return false, caddyhttp.Error(http.StatusBadRequest, err)
			}

			if !h.portIsAllowed(port) {
				return false, caddyhttp.Error(http.StatusForbidden,
					fmt.Errorf("port %s is not allowed", port))
			}

		match:
			for _, rule := range h.aclRules {
				if _, ok := rule.(*aclDomainRule); ok {
					switch rule.tryMatch(nil, host) {
					case aclDecisionDeny:
						return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
					case aclDecisionAllow:
						break match
					}
				}
			}

			IPs, err := net.LookupIP(host)
			if err != nil {
				return false, caddyhttp.Error(http.StatusBadGateway,
					fmt.Errorf("lookup of %s failed: %v", host, err))
			}

			for _, ip := range IPs {
				if !h.hostIsAllowed(host, ip) {
					continue
				}
				return true, nil
			}

			return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
		}(string(req))
		if !ok {
			return true, err
		}

		raddr, err := net.ResolveUDPAddr("udp", string(req))
		if err != nil {
			return true, caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("resolve UDP address error: %w", err))
		}

		rconn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return true, caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("dial UDP connection error: %w", err))
		}
		defer rconn.Close()
	}

	switch r.ProtoMajor {
	case 1:
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", RequestProtocol)
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusSwitchingProtocols)

		rc := http.NewResponseController(w)
		err = rc.Flush()
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}

		conn, _, err := rc.Hijack()
		if err != nil {
			return true, err
		}
		defer conn.Close()

		return true, h.udpProxyServer.HandleStream(conn, req, rconn, h.destinationAllowed)
	case 2:
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusOK)

		// The stdlib HTTP/2 ResponseWriter implements neither http.Hijacker nor
		// auto-flushing, so (unlike HTTP/1.1) we cannot take over a raw net.Conn.
		// Mirror the regular HTTP/2 CONNECT path: read the capsule stream from
		// the request body and write back through the ResponseWriter, flushing
		// each datagram so it reaches the client promptly.
		rc := http.NewResponseController(w)
		if err = rc.Flush(); err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}
		defer r.Body.Close()

		return true, h.udpProxyServer.HandleStream(newHTTPStream(w, r.Body), req, rconn, h.destinationAllowed)
	case 3:
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		w.WriteHeader(http.StatusOK)

		return true, h.udpProxyServer.HandlePacket(w.(http3.HTTPStreamer).HTTPStream(), req, rconn)
	default:
		return false, nil
	}
}

var (
	_ Payload = (*BytePayload)(nil)
	_ Payload = (*CompressedPayload)(nil)
	_ Payload = (*UncompressedPayload)(nil)
	_ Payload = (*CompressionAssignPayload)(nil)
	_ Payload = (*CompressionClosePayload)(nil)
)
