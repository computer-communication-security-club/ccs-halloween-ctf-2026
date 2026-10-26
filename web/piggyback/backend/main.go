// backend — the app server behind the front proxies.
//
// It speaks HTTP/1.1 with keep-alive and reads requests off each connection
// sequentially with http.ReadRequest, so PIPELINED requests (including a
// smuggled one) are processed in order on the same connection.
//
// INTENTIONAL VULN (the backend half of the chain): the /promote guard that is
// meant to keep this privileged endpoint off the replayable 0-RTT path is
// evaluated from the PER-REQUEST `Early-Data` header instead of the
// CONNECTION's early-data taint. The first request on an early-data connection
// is tagged by the front proxy, so it is correctly rejected with 425 — but a
// smuggled request that the front never tagged slips past the guard. See the
// `/promote` case for the exact line.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
)

var (
	mu    sync.Mutex
	step  = map[string]int{}  // per-token promotion progress: 0 -> 1 -> 2
	admin = map[string]bool{} // tokens that reached step 2
	flag  = envOr("FLAG", "ccsCTF{replace_me}")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func token(r *http.Request) string {
	if t := r.Header.Get("X-Token"); t != "" {
		return t
	}
	return "anon"
}

func resp(code int, status, body string) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		code, status, len(body), body)
}

// connEarly: did THIS connection begin with an early-data request? Derived from
// the first request's tag and intended to taint every request on the wire.
func route(r *http.Request, connEarly bool) string {
	tok := token(r)
	switch r.URL.Path {
	case "/":
		return resp(200, "OK", "0rtt-desync lab backend\n")
	case "/warm":
		return resp(200, "OK", "warm\n")
	case "/promote":
		// AUTHORIZATION (connection-level): /promote is an internal endpoint
		// reachable only from the trusted early-data fast path. A plain 1-RTT
		// connection can never satisfy this, which closes the trivial
		// "just POST /promote twice" shortcut.
		if !connEarly {
			return resp(403, "Forbidden", "promote: forbidden (not internal)\n")
		}
		// ---- INTENTIONAL VULN ----
		// SECURE form would be: `if connEarly { 425 }` — reject the whole
		// early-data connection. Instead we consult the per-request header,
		// which the front proxy only set on the FIRST request. The smuggled
		// request has no such header and sails through.
		if r.Header.Get("Early-Data") == "1" {
			return resp(425, "Too Early", "promote: too early\n")
		}
		// --------------------------
		mu.Lock()
		defer mu.Unlock()
		switch step[tok] {
		case 0:
			step[tok] = 1
			return resp(200, "OK", "promote: step=1 ok\n")
		case 1:
			step[tok] = 2
			admin[tok] = true
			return resp(200, "OK", "promote: step=2 ok admin-granted\n")
		default:
			return resp(200, "OK", "promote: already-admin\n")
		}
	case "/flag":
		mu.Lock()
		ok := admin[tok]
		mu.Unlock()
		if ok {
			return resp(200, "OK", flag+"\n")
		}
		return resp(403, "Forbidden", "flag: forbidden (promote to admin first)\n")
	default:
		return resp(404, "Not Found", "not found\n")
	}
}

func handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	connEarly := false
	for i := 0; ; i++ {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		req.Body.Close()
		if i == 0 {
			// Connection taint is fixed by the first request's tag.
			connEarly = req.Header.Get("Early-Data") == "1"
		}
		if _, err := io.WriteString(c, route(req, connEarly)); err != nil {
			return
		}
	}
}

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "[backend] listening on :8080")
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}
