package engine

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"net-merge/internal/nics"
)

// Loopback aliases (127.0.0.2, 127.0.0.3) stand in for physical NICs: the target server
// reports which source address each flow arrived from.
func startTarget(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				c.Write([]byte(host + "\n"))
				io.Copy(c, c) // echo
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// needLoopbackAliases skips when 127.0.0.2/3 can't be bound. Linux and Windows answer for all of
// 127/8; macOS needs `sudo ifconfig lo0 alias 127.0.0.2/32` (and .3) first.
func needLoopbackAliases(t testing.TB) {
	t.Helper()
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		ln, err := net.Listen("tcp4", ip+":0")
		if err != nil {
			t.Skipf("%s is not bindable; on macOS run: sudo ifconfig lo0 alias %s/32", ip, ip)
		}
		ln.Close()
	}
}

func startProxy(t *testing.T, nics []nics.Nic) (*Scheduler, string) {
	t.Helper()
	needLoopbackAliases(t)
	s := NewScheduler(nics)
	b := NewBalancer(s)
	b.ConnectTimeout = 2 * time.Second
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeSocks5(ln, b)
	return s, ln.Addr().String()
}

type socksConn struct {
	net.Conn
	r   *bufio.Reader
	rep byte
}

func socksConnect(t *testing.T, proxy string, port int) *socksConn {
	t.Helper()
	c, err := net.Dial("tcp4", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	r := bufio.NewReader(c)
	greet := make([]byte, 2)
	if _, err := io.ReadFull(r, greet); err != nil || greet[0] != 5 || greet[1] != 0 {
		t.Fatalf("bad greeting reply %v %v", greet, err)
	}
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(r, resp); err != nil {
		t.Fatal(err)
	}
	return &socksConn{Conn: c, r: r, rep: resp[1]}
}

func (s *socksConn) line(t *testing.T) string {
	t.Helper()
	l, err := s.r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return l[:len(l)-1]
}

func TestFlowsSplitAcrossNics(t *testing.T) {
	port := startTarget(t)
	sched, proxy := startProxy(t, []nics.Nic{nic("nic-a", "127.0.0.2", 1), nic("nic-b", "127.0.0.3", 1)})

	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		c := socksConnect(t, proxy, port)
		if c.rep != 0 {
			t.Fatalf("connect failed rep=%d", c.rep)
		}
		seen[c.line(t)]++
		c.Write([]byte("ping\n"))
		if got := c.line(t); got != "ping" {
			t.Fatalf("echo mismatch: %q", got)
		}
	}
	if seen["127.0.0.2"] != 3 || seen["127.0.0.3"] != 3 {
		t.Fatalf("want 3/3 split, got %v", seen)
	}
	for _, s := range sched.Snapshot() {
		if s.Active != 3 {
			t.Fatalf("want 3 active on %s, got %d", s.Name, s.Active)
		}
	}
}

func TestBrokenNicFailsOver(t *testing.T) {
	port := startTarget(t)
	// 203.0.113.9 (TEST-NET-3) isn't owned by this machine: bind fails with WSAEADDRNOTAVAIL.
	sched, proxy := startProxy(t, []nics.Nic{nic("bad", "203.0.113.9", 1), nic("good", "127.0.0.2", 1)})
	for i := 0; i < 4; i++ {
		c := socksConnect(t, proxy, port)
		if c.rep != 0 {
			t.Fatalf("flow %d failed rep=%d", i, c.rep)
		}
		if got := c.line(t); got != "127.0.0.2" {
			t.Fatalf("flow %d came from %s", i, got)
		}
	}
	for _, s := range sched.Snapshot() {
		if s.Name == "bad" && s.Failed != 1 {
			t.Fatalf("bad NIC should be sidelined after one failure, failed=%d", s.Failed)
		}
	}
}

func TestRefusedIsReportedNotRetried(t *testing.T) {
	sched, proxy := startProxy(t, []nics.Nic{nic("a", "127.0.0.2", 1), nic("b", "127.0.0.3", 1)})
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	deadPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	c := socksConnect(t, proxy, deadPort)
	if c.rep != repRefused {
		t.Fatalf("want rep=5 (refused), got %d", c.rep)
	}
	var total int64
	for _, s := range sched.Snapshot() {
		total += s.Total
	}
	if total != 1 {
		t.Fatalf("refusal must not be retried on other NICs, attempts=%d", total)
	}
}

func TestIPv6Destination(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		c.Write([]byte(host + "\n"))
		c.Close()
	}()
	// ::1 doubles as the NIC's IPv6 source address.
	n := nic("v6nic", "127.0.0.2", 1)
	n.IP6 = net.ParseIP("::1")
	_, proxy := startProxy(t, []nics.Nic{n})

	c, err := net.Dial("tcp4", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	port := ln.Addr().(*net.TCPAddr).Port
	req := append([]byte{5, 1, 0, 4}, net.ParseIP("::1").To16()...) // ATYP 4 = IPv6
	c.Write(append(req, byte(port>>8), byte(port)))
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != repOK {
		t.Fatalf("connect to IPv6 destination failed: %v err=%v", resp, err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "::1\n" {
		t.Fatalf("server saw source %q, want ::1", line)
	}
}

func TestUDPAssociateRefusedCleanly(t *testing.T) {
	_, proxy := startProxy(t, []nics.Nic{nic("a", "127.0.0.2", 1)})
	c, _ := net.Dial("tcp4", proxy)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != repCmdUnsupported {
		t.Fatalf("want rep=7, got %v err=%v", resp, err)
	}
}

func TestSocksRejectsNonzeroReservedByte(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeSocks5(ln, NewBalancer(NewScheduler(nil)))

	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 1, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("request with nonzero reserved byte was not rejected")
	}
}

func TestUnsupportedSocksCommandDoesNotWaitForDestination(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeSocks5(ln, NewBalancer(NewScheduler(nil)))

	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 3, 0, 1}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != repCmdUnsupported {
		t.Fatalf("want unsupported-command reply, got %v err=%v", reply, err)
	}
}

func TestHalfCloseStillDeliversReply(t *testing.T) {
	// Target reads until EOF, then answers: breaks if the proxy tears down on first FIN.
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(c)
		c.Write(append([]byte("got:"), data...))
		c.Close()
	}()
	_, proxy := startProxy(t, []nics.Nic{nic("a", "127.0.0.2", 1)})
	// 127.0.0.2 -> 127.0.0.1 target; reuse socksConnect but don't read the greeting line.
	c := socksConnect(t, proxy, ln.Addr().(*net.TCPAddr).Port)
	c.Write([]byte("hello"))
	c.Conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c.r)
	if err != nil || string(got) != "got:hello" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// Raw relay throughput through the proxy over loopback (the CPU ceiling of the data path).
func benchRelay(b *testing.B, streams int) {
	needLoopbackAliases(b)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	chunk := make([]byte, 256<<10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { // source: writes until the client hangs up
				defer c.Close()
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()
	s := NewScheduler([]nics.Nic{nic("a", "127.0.0.2", 1), nic("b", "127.0.0.3", 1)})
	pl, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer pl.Close()
	go ServeSocks5(pl, NewBalancer(s))

	port := ln.Addr().(*net.TCPAddr).Port
	conns := make([]net.Conn, streams)
	for i := range conns {
		c, _ := net.Dial("tcp4", pl.Addr().String())
		c.Write([]byte{5, 1, 0})
		io.ReadFull(c, make([]byte, 2))
		c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		io.ReadFull(c, make([]byte, 10))
		conns[i] = c
	}
	per := int64(b.N) / int64(streams)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	done := make(chan struct{}, streams)
	for _, c := range conns {
		go func() {
			io.CopyN(io.Discard, c, per*int64(len(chunk)))
			done <- struct{}{}
		}()
	}
	for range conns {
		<-done
	}
	b.StopTimer()
	for _, c := range conns {
		c.Close()
	}
}

func BenchmarkRelay1Stream(b *testing.B)  { benchRelay(b, 1) }
func BenchmarkRelay8Streams(b *testing.B) { benchRelay(b, 8) }
