// Package notify delivers messages to a phone: ntfy and Telegram.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Message is one push notification.
type Message struct {
	Title, Body string
	Urgent      bool
}

// Sender delivers a message to one channel.
type Sender interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

const userAgent = "message-me-cve"

// Ntfy posts to an ntfy topic URL.
type Ntfy struct {
	URL  string
	HTTP *http.Client
}

func (n *Ntfy) Name() string { return "ntfy" }

func (n *Ntfy) Send(ctx context.Context, m Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", ascii(m.Title)) // HTTP header: ASCII only
	req.Header.Set("User-Agent", userAgent)
	if m.Urgent {
		req.Header.Set("Priority", "urgent")
	}
	return do(n.HTTP, req)
}

// Telegram sends through a bot to one chat.
type Telegram struct {
	Token, ChatID string
	API           string // https://api.telegram.org
	HTTP          *http.Client
	// Gap is the minimum time between messages. Telegram: "avoid sending
	// more than one message per second" to a single chat.
	Gap  time.Duration
	last time.Time
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, m Message) error {
	form := url.Values{"chat_id": {t.ChatID}, "text": {m.Title + "\n\n" + m.Body}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.API+"/bot"+t.Token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("cannot build request") // the URL holds the token
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(t.last.Add(t.Gap))):
	}
	err = do(t.HTTP, req)
	// Pace from the reply: Telegram has this message now, so the next one
	// arrives at least Gap later.
	t.last = time.Now()
	return err
}

// Ping requests u, the URL of a dead man's switch (healthchecks.io, Uptime
// Kuma push monitor). The monitor alerts when pings stop, which covers the
// one failure a run cannot report: not running at all.
func Ping(ctx context.Context, c *http.Client, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("cannot build request") // the URL is a secret
	}
	req.Header.Set("User-Agent", userAgent)
	return do(c, req)
}

func do(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		// url.Error prints the URL, which is a secret for every caller:
		// the ntfy topic, the Telegram bot token, the heartbeat URL.
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(reply)))
	}
	return nil
}

func ascii(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
