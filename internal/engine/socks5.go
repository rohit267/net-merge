package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

func ServeSocks5(ln net.Listener, b *Balancer) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go b.handleSocks5(c)
	}
}

func socksReply(c net.Conn, rep byte) {
	c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (b *Balancer) handleSocks5(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 0x05 || hdr[1] == 0 {
		c.Close()
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		c.Close()
		return
	}
	if !bytes.Contains(methods, []byte{0x00}) {
		c.Write([]byte{0x05, 0xff})
		c.Close()
		return
	}
	c.Write([]byte{0x05, 0x00})

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 0x05 || req[2] != 0 {
		c.Close()
		return
	}
	if req[1] != 0x01 { // CONNECT only; UDP ASSOCIATE comes with the TUN front-end
		socksReply(c, repCmdUnsupported)
		c.Close()
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			c.Close()
			return
		}
		host = net.IP(a[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil || l[0] == 0 {
			c.Close()
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			c.Close()
			return
		}
		host = string(name)
	case 0x04:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			c.Close()
			return
		}
		host = net.IP(a[:]).String()
	default:
		socksReply(c, repAtypUnsupported)
		c.Close()
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		c.Close()
		return
	}
	port := int(binary.BigEndian.Uint16(p[:]))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up, sl, fam, err := b.DialTCP(ctx, host, port)
	if err != nil {
		rep := byte(repFailure)
		var de *dialError
		if errors.As(err, &de) {
			rep = de.rep
		}
		socksReply(c, rep)
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	socksReply(c, repOK)
	Relay(c, up, sl, fam, b.S)
}
