package integration_test

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dropwire/internal/relay"
)

func TestRateLimitIsPerMember(t *testing.T) {
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	s := start(t, relay.Config{DataDir: t.TempDir(), RequestsPerMinute: 1, Now: func() time.Time { return time.Unix(seconds.Load(), 0) }})
	mint := func(key string, status int) {
		s.call(t, "POST", "/v1/inboxes", key, "", "application/json", strings.NewReader("{}"), status)
	}
	mint(gateA, 201)
	mint(gateA, 429)
	mint(gateB, 201)
	seconds.Add(60)
	mint(gateA, 201)
}

func TestQuotaIsChargedToSendingMember(t *testing.T) {
	s := start(t, relay.Config{DataDir: t.TempDir(), QuotaBytes: 8})
	a, b := s.mint(t, gateA), s.mint(t, gateB)
	send := func(from, to inbox, member, text string, status int) string {
		p := fmt.Sprintf(`{"to":%q,"from":%q,"body":%q}`, to.Address, from.Address, text)
		data, _ := s.call(t, "POST", "/v1/messages", member, from.Secret, "application/json", strings.NewReader(p), status)
		return unpack[map[string]string](t, data)["message_id"]
	}
	id := send(a, b, gateA, "12345678", 201)
	send(a, b, gateA, "x", 507)
	send(b, a, gateB, "12345678", 201)
	s.call(t, "DELETE", b.path("messages/"+id), gateB, b.Secret, "", nil, 204)
	send(a, b, gateA, "12345678", 201)
}
