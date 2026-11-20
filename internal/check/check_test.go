package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MarcusHoltz/message-me-cve/internal/feed"
	"github.com/MarcusHoltz/message-me-cve/internal/notify"
	"github.com/MarcusHoltz/message-me-cve/internal/state"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

type fakeFeeds struct {
	kev       []feed.KEVEntry
	kevErr    error
	nvd       []feed.CVE
	nvdErr    error
	nvdCalls  int
	nvdStart  time.Time
	affected  map[string][]string
	cveOrgErr error
}

func (f *fakeFeeds) KEV(context.Context) ([]feed.KEVEntry, error) { return f.kev, f.kevErr }

func (f *fakeFeeds) NVD(_ context.Context, start, _ time.Time) ([]feed.CVE, error) {
	f.nvdCalls++
	f.nvdStart = start
	return f.nvd, f.nvdErr
}

func (f *fakeFeeds) Affected(_ context.Context, id string) ([]string, error) {
	if f.cveOrgErr != nil {
		return nil, f.cveOrgErr
	}
	return f.affected[id], nil
}

type fakeSender struct {
	sent []notify.Message
	fail bool
}

func (s *fakeSender) Name() string { return "fake" }

func (s *fakeSender) Send(_ context.Context, m notify.Message) error {
	if s.fail {
		return errors.New("down")
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakeSender) titles() string {
	var t []string
	for _, m := range s.sent {
		t = append(t, m.Title)
	}
	return strings.Join(t, "\n")
}

func setup(f *fakeFeeds) (*Checker, *fakeSender, *state.State) {
	s := &fakeSender{}
	st, _ := state.Load("/nonexistent")
	return &Checker{Feeds: f, Senders: []notify.Sender{s}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, s, st
}

func kevEntry(id, product string) feed.KEVEntry {
	return feed.KEVEntry{CveID: id, VendorProject: product, Product: product}
}

func nvdCVE(id, product, severity string, score float64, published time.Time) feed.CVE {
	var c feed.CVE
	c.ID = id
	c.Published = published.Format("2006-01-02T15:04:05.000")
	c.Descriptions = []feed.LangString{{Lang: "en", Value: "bug in " + product}}
	var m feed.CVSSMetric
	m.CVSSData.BaseScore, m.CVSSData.BaseSeverity = score, severity
	c.Metrics.V31 = []feed.CVSSMetric{m}
	if product != "" {
		var conf feed.Configuration
		conf.Nodes = make([]struct {
			CPEMatch []feed.CPEMatch `json:"cpeMatch"`
		}, 1)
		conf.Nodes[0].CPEMatch = []feed.CPEMatch{{Vulnerable: true, Criteria: "cpe:2.3:a:" + product + ":" + product + ":*:*:*:*:*:*:*:*"}}
		c.Configurations = []feed.Configuration{conf}
	}
	return c
}

var (
	shop = Profile{Name: "shop", Words: []string{"php"}}
	blog = Profile{Name: "blog", Words: []string{"php", "nginx"}}
)

func TestKEVSentOnceAcrossProfiles(t *testing.T) {
	f := &fakeFeeds{kev: []feed.KEVEntry{kevEntry("CVE-1", "php"), kevEntry("CVE-2", "nginx")}}
	c, s, st := setup(f)

	res := c.Run(context.Background(), now, []Profile{shop, blog}, st)
	if !res.OK() || !res.Delivered() || len(s.sent) != 2 {
		t.Fatalf("problems %v, sent:\n%s", res.Problems, s.titles())
	}
	if want := "[shop, blog] ACT NOW [php]: exploited php CVE-1"; s.sent[0].Title != want || !s.sent[0].Urgent {
		t.Errorf("got %q, want %q (urgent)", s.sent[0].Title, want)
	}
	if !st.WasSent("shop", "kev:CVE-1") || !st.WasSent("blog", "kev:CVE-1") || st.WasSent("shop", "kev:CVE-2") {
		t.Errorf("sent state wrong: %v", st.Sent)
	}

	s.sent = nil
	c.Run(context.Background(), now.Add(time.Hour), []Profile{shop, blog}, st)
	if len(s.sent) != 0 {
		t.Errorf("resent on second run:\n%s", s.titles())
	}
}

func TestUndeliveredIsRetried(t *testing.T) {
	f := &fakeFeeds{
		kev: []feed.KEVEntry{kevEntry("CVE-1", "php")},
		nvd: []feed.CVE{nvdCVE("CVE-2", "php", "HIGH", 7.5, now)},
	}
	c, s, st := setup(f)
	s.fail = true
	res := c.Run(context.Background(), now, []Profile{shop}, st)
	if res.OK() || res.Delivered() || st.WasSent("shop", "kev:CVE-1") {
		t.Fatalf("undelivered alert marked sent or run OK: %v", res.Problems)
	}
	if !st.NVDCursor.IsZero() {
		t.Error("NVD cursor moved although an NVD alert was not delivered")
	}
	s.fail = false
	c.Run(context.Background(), now.Add(3*time.Hour), []Profile{shop}, st)
	if !strings.Contains(s.titles(), "CVE-1") || !strings.Contains(s.titles(), "CVE-2") {
		t.Errorf("not retried:\n%s", s.titles())
	}
}

func TestNVDFilters(t *testing.T) {
	recent := now.Add(-24 * time.Hour)
	f := &fakeFeeds{
		kev: []feed.KEVEntry{kevEntry("CVE-K", "php")},
		nvd: []feed.CVE{
			nvdCVE("CVE-CRIT", "php", "CRITICAL", 9.8, recent),
			nvdCVE("CVE-MED", "php", "MEDIUM", 5.0, recent),
			nvdCVE("CVE-OLD", "php", "HIGH", 7.5, now.Add(-100*24*time.Hour)),
			nvdCVE("CVE-OTHER", "wordpress", "HIGH", 7.5, recent),
			nvdCVE("CVE-K", "php", "HIGH", 7.5, recent), // already alerted as KEV
		},
	}
	c, s, st := setup(f)
	res := c.Run(context.Background(), now, []Profile{shop}, st)
	got := s.titles()
	if !res.OK() || len(s.sent) != 2 || !strings.Contains(got, "CRITICAL 9.8 [php]: CVE-CRIT") {
		t.Errorf("problems %v, sent:\n%s", res.Problems, got)
	}
	if !st.NVDCursor.Equal(now) || !st.NVDPolled.Equal(now) {
		t.Errorf("cursor %v polled %v, want both %v", st.NVDCursor, st.NVDPolled, now)
	}
	if want := now.Add(-nvdLookback - nvdOverlap); !f.nvdStart.Equal(want) {
		t.Errorf("first NVD window starts %v, want %v", f.nvdStart, want)
	}
}

func TestNVDNotDue(t *testing.T) {
	f := &fakeFeeds{}
	c, _, st := setup(f)
	st.NVDCursor, st.NVDPolled = now.Add(-time.Hour), now.Add(-time.Hour)

	res := c.Run(context.Background(), now, []Profile{shop}, st)
	if f.nvdCalls != 0 || res.NVDPolled || !res.OK() {
		t.Errorf("NVD polled %d times within %v; problems %v", f.nvdCalls, NVDMinGap, res.Problems)
	}

	// The last poll did not finish: not-due runs stay failed.
	st.NVDCursor = now.Add(-3 * time.Hour)
	if res := c.Run(context.Background(), now, []Profile{shop}, st); res.OK() {
		t.Error("unfinished NVD check not reported")
	}

	// Due again: polled from the cursor.
	c.Run(context.Background(), now.Add(time.Hour), []Profile{shop}, st)
	if f.nvdCalls != 1 || !f.nvdStart.Equal(now.Add(-3*time.Hour-nvdOverlap)) {
		t.Errorf("calls %d start %v", f.nvdCalls, f.nvdStart)
	}
}

func TestCVEOrgOutageHoldsCursor(t *testing.T) {
	recent := now.Add(-time.Hour)
	unanalyzed := nvdCVE("CVE-U", "", "HIGH", 8.0, recent)
	unanalyzed.Descriptions[0].Value = "php flaw"
	f := &fakeFeeds{
		nvd:       []feed.CVE{unanalyzed, nvdCVE("CVE-A", "php", "HIGH", 7.5, recent)},
		cveOrgErr: &feed.Error{Feed: "CVE.org", Err: errors.New("HTTP 500")},
	}
	c, s, st := setup(f)
	res := c.Run(context.Background(), now, []Profile{shop}, st)
	if res.OK() || !st.NVDCursor.IsZero() {
		t.Errorf("OK %v cursor %v; want failure and cursor held", res.OK(), st.NVDCursor)
	}
	if !strings.Contains(s.titles(), "CVE-A") || !strings.Contains(s.titles(), "cannot check CVE.org") {
		t.Errorf("other CVEs must still be sent, outage reported:\n%s", s.titles())
	}

	f.cveOrgErr, f.affected = nil, map[string][]string{"CVE-U": {"PHP Group PHP"}}
	s.sent = nil
	c.Run(context.Background(), now.Add(3*time.Hour), []Profile{shop}, st)
	got := s.titles()
	if !strings.Contains(got, "CVE-U") || strings.Contains(got, "CVE-A") || !strings.Contains(got, "CVE.org OK again") {
		t.Errorf("after recovery:\n%s", got)
	}
}

func TestFailureReportedOnce(t *testing.T) {
	f := &fakeFeeds{kevErr: &feed.Error{Feed: "CISA KEV", Err: errors.New("HTTP 502")}}
	c, s, st := setup(f)
	for i := range 3 {
		if c.Run(context.Background(), now.Add(time.Duration(i)*time.Hour), []Profile{shop}, st).OK() {
			t.Fatal("run OK while KEV is down")
		}
	}
	f.kevErr = nil
	c.Run(context.Background(), now.Add(5*time.Hour), []Profile{shop}, st)
	want := "message-me-cve: cannot check CISA KEV\nmessage-me-cve: CISA KEV OK again"
	if got := s.titles(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestBadWatchListDoesNotStopOthers(t *testing.T) {
	f := &fakeFeeds{kev: []feed.KEVEntry{kevEntry("CVE-1", "php")}}
	c, s, st := setup(f)
	bad := Profile{Name: "bad", Err: errors.New("bad.txt has no words")}
	res := c.Run(context.Background(), now, []Profile{bad, shop}, st)
	if res.OK() || !strings.Contains(s.titles(), "cannot check watch list bad") || !st.WasSent("shop", "kev:CVE-1") {
		t.Errorf("problems %v, sent:\n%s", res.Problems, s.titles())
	}
}

func TestManyAlertsCombined(t *testing.T) {
	f := &fakeFeeds{}
	for i := range 200 {
		f.kev = append(f.kev, kevEntry(fmt.Sprintf("CVE-%03d", i), "php"))
	}
	c, s, st := setup(f)
	c.Run(context.Background(), now, []Profile{shop}, st)
	if len(s.sent) < 2 || len(s.sent) > 10 {
		t.Fatalf("%d messages for 200 alerts, want a few combined parts", len(s.sent))
	}
	for _, m := range s.sent {
		if len(m.Body) > maxBody || !strings.Contains(m.Title, "200 matches") {
			t.Errorf("part %q: %d bytes", m.Title, len(m.Body))
		}
	}
	if len(st.Sent["shop"]) != 200 {
		t.Errorf("%d marked sent, want 200", len(st.Sent["shop"]))
	}
}

func TestDryRunSendsNothing(t *testing.T) {
	f := &fakeFeeds{kev: []feed.KEVEntry{kevEntry("CVE-1", "php")}}
	c, s, st := setup(f)
	c.DryRun = true
	res := c.Run(context.Background(), now, []Profile{shop}, st)
	if len(s.sent) != 0 || len(res.Deliveries) != 1 || st.WasSent("shop", "kev:CVE-1") {
		t.Errorf("sent %d, deliveries %d, state %v", len(s.sent), len(res.Deliveries), st.Sent)
	}
}

func TestDeletedWatchListForgotten(t *testing.T) {
	c, s, st := setup(&fakeFeeds{})
	bad := Profile{Name: "gone", Err: errors.New("no words")}
	c.Run(context.Background(), now, []Profile{bad, shop}, st)
	c.Run(context.Background(), now.Add(time.Hour), []Profile{shop}, st) // gone.txt deleted
	c.Run(context.Background(), now.Add(2*time.Hour), []Profile{bad, shop}, st)
	if got := strings.Count(s.titles(), "cannot check watch list gone"); got != 2 {
		t.Errorf("re-added broken list reported %d times, want 2:\n%s", got, s.titles())
	}
}
