package bootstrap

import (
	"net"
	"net/http"
	"time"
)

func newOutboundHTTPClient(timeout time.Duration) *http.Client {
	// http.DefaultTransport is documented as *http.Transport, but instrumentation
	// libraries are free to replace it with a wrapper. Fall back rather than
	// panicking during startup if that has happened.
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}

	transport := base.Clone()
	transport.MaxIdleConns = 200
	transport.MaxIdleConnsPerHost = 32
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
