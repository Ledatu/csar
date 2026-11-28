package router

import (
	"bufio"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

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
	a.contentEncoding = strings.Join(a.Header().Values("Content-Encoding"), ",")
	if ct, _, err := mime.ParseMediaType(a.contentType); err == nil && ct == "text/event-stream" {
		a.capture = false
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditResponseCapture) Write(body []byte) (int, error) {
	if !a.written {
		a.WriteHeader(http.StatusOK)
	}
	n, err := a.ResponseWriter.Write(body)
	a.observedBytes += int64(n)
	if err != nil || n != len(body) {
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
	// Flush describes delivery timing, not whether finite JSON will complete.
	// Keep the bounded copy; the handler's completion determines eligibility.
	err := http.NewResponseController(a.ResponseWriter).Flush()
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		a.failed = true
	}
	return err
}

func (a *auditResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	a.capture = false
	a.body = nil
	conn, rw, err := http.NewResponseController(a.ResponseWriter).Hijack()
	a.hijacked = err == nil
	return conn, rw, err
}

func (a *auditResponseCapture) ReadFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(struct{ io.Writer }{a}, src)
	if err != nil {
		a.failed = true
	}
	return n, err
}
