package router

import (
	"bufio"
	"io"
	"net"
	"net/http"

	auditcore "github.com/ledatu/csar-core/audit"
)

// The bounded copy is independent of the bytes forwarded to the caller.
type auditResponseCapture struct {
	http.ResponseWriter
	statusCode      int
	written         bool
	capture         bool
	failed          bool
	hijacked        bool
	body            []byte
	observedBytes   int64
	contentType     string
	contentEncoding string
}

func (a *auditResponseCapture) WriteHeader(code int) {
	if a.written {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		a.ResponseWriter.WriteHeader(code)
		return
	}
	a.statusCode = code
	a.written = true
	a.contentType = a.Header().Get("Content-Type")
	a.contentEncoding = a.Header().Get("Content-Encoding")
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditResponseCapture) Write(body []byte) (int, error) {
	if !a.written {
		a.WriteHeader(http.StatusOK)
	}
	n, err := a.ResponseWriter.Write(body)
	a.observedBytes += int64(n)
	if err != nil {
		a.failed = true
	}
	if a.capture && a.statusCode >= 400 {
		remaining := auditcore.MaxHTTPInspectBytes + 1 - len(a.body)
		if remaining > n {
			remaining = n
		}
		if remaining > 0 {
			a.body = append(a.body, body[:remaining]...)
		}
	}
	return n, err
}

func (a *auditResponseCapture) Unwrap() http.ResponseWriter { return a.ResponseWriter }

func (a *auditResponseCapture) Flush() { _ = a.FlushError() }

func (a *auditResponseCapture) FlushError() error {
	if !a.written {
		a.WriteHeader(http.StatusOK)
	}
	// A flushed stream may outlive the request and is not a complete envelope.
	a.capture = false
	a.body = nil
	return http.NewResponseController(a.ResponseWriter).Flush()
}

func (a *auditResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	a.capture = false
	a.body = nil
	conn, rw, err := http.NewResponseController(a.ResponseWriter).Hijack()
	a.hijacked = err == nil
	return conn, rw, err
}

func (a *auditResponseCapture) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{a}, src)
}
