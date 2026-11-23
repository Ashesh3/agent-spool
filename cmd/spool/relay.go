package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type relay struct {
	*profile
	http *http.Client
}

func newRelay(p *profile) (*relay, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if pemPath := os.Getenv("SPOOL_CA_FILE"); pemPath != "" {
		pem, err := os.ReadFile(pemPath)
		if err != nil {
			return nil, fmt.Errorf("reading SPOOL_CA_FILE: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system CA certificates: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("SPOOL_CA_FILE contains no readable CA certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &relay{p, &http.Client{
		Transport: transport,
		Timeout:   15 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (r *relay) request(method, path, contentType string, body io.Reader, owned bool) (*http.Response, error) {
	req, err := http.NewRequest(method, r.Relay+path, body)
	if err != nil {
		return nil, errors.New("invalid relay request")
	}
	req.Header.Set("Authorization", "Bearer "+r.Gate)
	if owned {
		req.Header.Set("X-Inbox-Secret", r.InboxSecret)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		// Don't echo an untrusted Location, proxy URL, or request headers.
		var cert *tls.CertificateVerificationError
		var dns *net.DNSError
		var n net.Error
		switch {
		case errors.As(err, &cert):
			return nil, errors.New("relay TLS certificate verification failed; check hostname, trust roots, and SPOOL_CA_FILE")
		case errors.As(err, &dns):
			return nil, errors.New("DNS lookup failed; check relay and proxy settings")
		case errors.As(err, &n) && n.Timeout():
			return nil, errors.New("relay request timed out")
		default:
			return nil, errors.New("relay request failed; check HTTPS connectivity and proxy settings")
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	resp.Body.Close()
	text := http.StatusText(resp.StatusCode)
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
		text = "redirect refused; configure the final HTTPS origin"
	case 401:
		text = "gate key rejected"
	case 403:
		text = "inbox credentials or resource ownership rejected"
	case 413:
		text = "encrypted upload exceeds relay limits"
	case 429:
		text = "gate key rate limit reached"
	case 507:
		text = "gate key storage quota exhausted"
	}
	return nil, fmt.Errorf("relay HTTP %d: %s", resp.StatusCode, text)
}

func decodeJSON(body io.Reader, max int64, dst any) error {
	bounded := &io.LimitedReader{R: body, N: max + 1}
	d := json.NewDecoder(bounded)
	if err := d.Decode(dst); err != nil {
		return errors.New("invalid or incomplete JSON response")
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF || bounded.N == 0 {
		return errors.New("oversize or trailing JSON data")
	}
	return nil
}

func (r *relay) postJSON(path string, payload any, owned bool, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := r.request(http.MethodPost, path, "application/json", bytes.NewReader(body), owned)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeJSON(resp.Body, 64<<10, result)
}
