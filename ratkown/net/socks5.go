package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	socksMu       sync.Mutex
	socksEnabled  bool
	socksRelay    *net.UDPAddr
	socksControl  net.Conn
	socksFakeFrom *net.UDPAddr
)

func Socks5Enabled() bool {
	return socksEnabled
}

func Socks5Enable(proxyAddr string) error {
	host, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return fmt.Errorf("socks5 addr: %w", err)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	ctrl, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 5*time.Second)
	if err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		ctrl.Close()
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	g := make([]byte, 2)
	if _, err := readFullTCP(ctrl, g); err != nil || g[0] != 0x05 {
		ctrl.Close()
		return fmt.Errorf("socks5 bad greeting reply")
	}

	req := []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00}
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		return fmt.Errorf("socks5 associate: %w", err)
	}
	head := make([]byte, 4)
	if _, err := readFullTCP(ctrl, head); err != nil || head[1] != 0x00 {
		ctrl.Close()
		return fmt.Errorf("socks5 associate refused (code %d)", head[1])
	}
	atyp := head[3]
	var relayHost string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := readFullTCP(ctrl, b); err != nil {
			ctrl.Close()
			return fmt.Errorf("socks5 relay ip: %w", err)
		}
		relayHost = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFullTCP(ctrl, l); err != nil {
			ctrl.Close()
			return fmt.Errorf("socks5 relay len: %w", err)
		}
		b := make([]byte, int(l[0]))
		if _, err := readFullTCP(ctrl, b); err != nil {
			ctrl.Close()
			return fmt.Errorf("socks5 relay host: %w", err)
		}
		relayHost = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := readFullTCP(ctrl, b); err != nil {
			ctrl.Close()
			return fmt.Errorf("socks5 relay ip6: %w", err)
		}
		relayHost = net.IP(b).String()
	}
	pb := make([]byte, 2)
	if _, err := readFullTCP(ctrl, pb); err != nil {
		ctrl.Close()
		return fmt.Errorf("socks5 relay port: %w", err)
	}
	if relayHost == "0.0.0.0" || relayHost == "" {
		relayHost = host
	}
	relayPort := binary.BigEndian.Uint16(pb)

	relay, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", relayHost, relayPort))
	if err != nil {
		ctrl.Close()
		return fmt.Errorf("socks5 relay resolve: %w", err)
	}

	socksMu.Lock()
	socksControl = ctrl
	socksRelay = relay
	socksFakeFrom = relay
	socksEnabled = true
	socksMu.Unlock()
	return nil
}

func readFullTCP(c net.Conn, b []byte) (int, error) {
	t := 0
	for t < len(b) {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(b[t:])
		t += n
		if err != nil {
			return t, err
		}
	}
	return t, nil
}

type UDPConnLike interface {
	WriteTo(b []byte, addr *net.UDPAddr) (int, error)
	ReadFrom(b []byte) (int, *net.UDPAddr, error)
	SetReadDeadline(t time.Time) error
	SetReadBuffer(bytes int) error
	Close() error
	LocalAddr() net.Addr
}

type plainUDP struct {
	c *net.UDPConn
}

func (p *plainUDP) WriteTo(b []byte, addr *net.UDPAddr) (int, error) { return p.c.WriteTo(b, addr) }
func (p *plainUDP) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, a, err := p.c.ReadFrom(b)
	ua, _ := a.(*net.UDPAddr)
	return n, ua, err
}
func (p *plainUDP) SetReadDeadline(t time.Time) error { return p.c.SetReadDeadline(t) }
func (p *plainUDP) SetReadBuffer(bytes int) error    { return p.c.SetReadBuffer(bytes) }
func (p *plainUDP) Close() error                     { return p.c.Close() }
func (p *plainUDP) LocalAddr() net.Addr              { return p.c.LocalAddr() }

type socksUDP struct {
	c    *net.UDPConn
	ping bool
}

func newSocksUDP() (*socksUDP, error) {
	addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	s := &socksUDP{c: c}
	s.c.WriteTo([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0x30, 0x39}, socksRelay)
	s.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	s.c.ReadFrom(buf)
	s.c.SetReadDeadline(time.Time{})
	return s, nil
}

func (s *socksUDP) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	ip4 := addr.IP.To4()
	hdr := make([]byte, 0, 10+len(b))
	hdr = append(hdr, 0, 0, 0)
	if ip4 != nil {
		hdr = append(hdr, 0x01)
		hdr = append(hdr, ip4...)
	} else {
		host := addr.IP.String()
		if addr.IP == nil || host == "" || host == "<nil>" {
			host = "127.0.0.1"
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		hb := make([]byte, 1+len(host))
		hb[0] = byte(len(host))
		copy(hb[1:], host)
		hdr = append(hdr, 0x03)
		hdr = append(hdr, hb...)
		hdr = append(hdr, 0, 0)
		hdr[len(hdr)-2] = byte(addr.Port >> 8)
		hdr[len(hdr)-1] = byte(addr.Port & 0xFF)
		hdr = append(hdr, b...)
		return s.c.WriteTo(hdr, socksRelay)
	}
	hdr = append(hdr, byte(addr.Port>>8), byte(addr.Port&0xFF))
	hdr = append(hdr, b...)
	return s.c.WriteTo(hdr, socksRelay)
}

func (s *socksUDP) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, _, err := s.c.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	if n < 4 {
		return 0, socksFakeFrom, nil
	}
	atyp := b[3]
	var skip int
	switch atyp {
	case 0x01:
		skip = 4 + 4 + 2
	case 0x03:
		if n < 5 {
			return 0, socksFakeFrom, nil
		}
		skip = 4 + 1 + int(b[4]) + 2
	case 0x04:
		skip = 4 + 16 + 2
	default:
		return n, socksFakeFrom, nil
	}
	if skip >= n {
		return 0, socksFakeFrom, nil
	}
	data := b[skip:n]
	copy(b, data)
	return len(data), socksFakeFrom, nil
}

func (s *socksUDP) SetReadDeadline(t time.Time) error { return s.c.SetReadDeadline(t) }
func (s *socksUDP) SetReadBuffer(bytes int) error    { return s.c.SetReadBuffer(bytes) }
func (s *socksUDP) Close() error                      { return s.c.Close() }
func (s *socksUDP) LocalAddr() net.Addr              { return s.c.LocalAddr() }
