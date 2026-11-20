package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelegram(t *testing.T) {
	var path, chat, text string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		path, chat, text = r.URL.Path, r.PostForm.Get("chat_id"), r.PostForm.Get("text")
		w.WriteHeader(status)
	}))
	defer srv.Close()
	tg := &Telegram{Token: "123:secret", ChatID: "42", API: srv.URL, HTTP: srv.Client()}

	if err := tg.Send(context.Background(), Message{Title: "T", Body: "B"}); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:secret/sendMessage" || chat != "42" || text != "T\n\nB" {
		t.Errorf("got path %q chat %q text %q", path, chat, text)
	}
	status = http.StatusBadRequest
	if err := tg.Send(context.Background(), Message{}); err == nil {
		t.Error("HTTP 400 reported as delivered")
	}
}

func TestTelegramErrorHidesToken(t *testing.T) {
	tg := &Telegram{Token: "123:secret", ChatID: "1", API: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	err := tg.Send(context.Background(), Message{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error %q leaks the token or is nil", err)
	}
}

func TestNtfyErrorHidesTopic(t *testing.T) {
	n := &Ntfy{URL: "http://127.0.0.1:1/secret-topic", HTTP: http.DefaultClient}
	err := n.Send(context.Background(), Message{})
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("error %q leaks the topic or is nil", err)
	}
}

func TestTelegramPacing(t *testing.T) {
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at = append(at, time.Now())
	}))
	defer srv.Close()
	tg := &Telegram{Token: "1:a", ChatID: "1", API: srv.URL, HTTP: srv.Client(), Gap: 50 * time.Millisecond}
	tg.Send(context.Background(), Message{})
	tg.Send(context.Background(), Message{})
	if len(at) != 2 || at[1].Sub(at[0]) < 50*time.Millisecond {
		t.Errorf("second message not paced: %v", at)
	}
}

func TestNtfy(t *testing.T) {
	var title, prio, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		title, prio = r.Header.Get("Title"), r.Header.Get("Priority")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()
	n := &Ntfy{URL: srv.URL, HTTP: srv.Client()}
	if err := n.Send(context.Background(), Message{Title: "ACT NOW \u00e9 x", Body: "b", Urgent: true}); err != nil {
		t.Fatal(err)
	}
	if title != "ACT NOW ? x" || prio != "urgent" || body != "b" {
		t.Errorf("got title %q priority %q body %q", title, prio, body)
	}
}

func TestPing(t *testing.T) {
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
	}))
	defer srv.Close()
	if err := Ping(context.Background(), srv.Client(), srv.URL); err != nil || method != http.MethodGet {
		t.Errorf("err %v, method %q", err, method)
	}
	err := Ping(context.Background(), http.DefaultClient, "http://127.0.0.1:1/secret-uuid")
	if err == nil || strings.Contains(err.Error(), "secret-uuid") {
		t.Errorf("error %q leaks the URL or is nil", err)
	}
}
