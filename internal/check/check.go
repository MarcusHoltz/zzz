// Package check runs one check of every watch list against the feeds and
// delivers the alerts.
//
// Rules that hold for every run:
//   - An alert is marked sent only after every channel accepted it, so a
//     failed delivery is retried, never lost.
//   - A failure (feed down, bad watch list) is messaged once when it starts
//     and once when it clears, and the run fails while it lasts.
//   - NVD is polled at most every two hours, as NVD asks of API clients.
//     The NVD cursor only moves past changes that were fully handled, so a
//     late, skipped or failed run leaves no gap.
package check

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/MarcusHoltz/message-me-cve/internal/feed"
	"github.com/MarcusHoltz/message-me-cve/internal/match"
	"github.com/MarcusHoltz/message-me-cve/internal/notify"
	"github.com/MarcusHoltz/message-me-cve/internal/state"
)

const (
	NVDMinGap   = 2 * time.Hour
	nvdLookback = 7 * 24 * time.Hour // first run
	nvdOverlap  = 5 * time.Minute    // re-read the cursor's edge
	// NVD re-edits old CVEs constantly; only recent ones are news.
	nvdMaxAge = 90 * 24 * time.Hour
	// More new alerts of one kind than this: one combined list instead.
	maxSingle = 5
	// ntfy turns bodies over 4096 bytes into attachments.
	maxBody = 3500

	watchListPrefix = "watch list " // Broken key prefix
)

// Profile is one watch list. Err is set when it could not be read.
type Profile struct {
	Name  string
	Words []string
	Err   error
}

// Feeds is what a check reads. *feed.Client implements it.
type Feeds interface {
	KEV(ctx context.Context) ([]feed.KEVEntry, error)
	NVD(ctx context.Context, start, end time.Time) ([]feed.CVE, error)
	Affected(ctx context.Context, id string) ([]string, error)
}

// Checker holds the dependencies of a check.
type Checker struct {
	Feeds   Feeds
	Senders []notify.Sender
	// DryRun logs messages instead of sending them. The caller must not
	// save the state afterwards.
	DryRun bool
	Log    *slog.Logger
}

// Delivery is one message and what each channel did with it.
type Delivery struct {
	At      time.Time
	Message notify.Message
	Results []string // "telegram: delivered", "ntfy: HTTP 500: ..."
	OK      bool
}

// ProfileReport is one profile's outcome.
type ProfileReport struct {
	Name    string
	Words   int
	New     int // matches not sent before
	Sent    int
	ReadErr error
}

// Result is the outcome of one run.
type Result struct {
	NVDPolled  bool
	Profiles   []ProfileReport
	Deliveries []Delivery
	Problems   []string // everything broken right now; empty means OK
}

func (r *Result) OK() bool { return len(r.Problems) == 0 }

// Delivered reports whether every message of the run reached every channel.
func (r *Result) Delivered() bool {
	for _, d := range r.Deliveries {
		if !d.OK {
			return false
		}
	}
	return true
}

// Run checks every profile once. It updates st; the caller saves it.
func (c *Checker) Run(ctx context.Context, now time.Time, profiles []Profile, st *state.State) *Result {
	r := &run{Checker: c, ctx: ctx, now: now, st: st, res: &Result{},
		affected: map[string]affectedResult{}}
	return r.run(profiles)
}

type run struct {
	*Checker
	ctx      context.Context
	now      time.Time
	st       *state.State
	res      *Result
	affected map[string]affectedResult // CVE.org lookups, one per CVE per run
	reports  map[string]*ProfileReport
}

type affectedResult struct {
	products []string
	err      error
}

func (r *run) run(profiles []Profile) *Result {
	r.reports = map[string]*ProfileReport{}
	var active []Profile
	for _, p := range profiles {
		r.res.Profiles = append(r.res.Profiles, ProfileReport{Name: p.Name, Words: len(p.Words), ReadErr: p.Err})
		r.track(watchListPrefix+p.Name, p.Err)
		if p.Err == nil {
			active = append(active, p)
		}
	}
	for i := range r.res.Profiles {
		r.reports[r.res.Profiles[i].Name] = &r.res.Profiles[i]
	}
	// A deleted watch list cannot recover; forget that it was broken, so a
	// new list with the same name is reported if it breaks.
	for name := range r.st.Broken {
		if p, ok := strings.CutPrefix(name, watchListPrefix); ok && r.reports[p] == nil {
			delete(r.st.Broken, name)
		}
	}

	kev, err := r.Feeds.KEV(r.ctx)
	r.track("CISA KEV", err)
	kevAlerts := r.matchKEV(kev, active)

	var nvdAlerts []*alert
	nvdComplete := false
	if r.nvdDue() {
		r.res.NVDPolled = true
		start := r.st.NVDCursor
		if start.IsZero() {
			start = r.now.Add(-nvdLookback)
		}
		r.st.NVDPolled = r.now
		cves, err := r.Feeds.NVD(r.ctx, start.Add(-nvdOverlap), r.now)
		r.track("NVD", err)
		if err == nil {
			var cveOrgErr error
			nvdAlerts, cveOrgErr = r.matchNVD(cves, active, kevAlerts)
			// Only meaningful when NVD was read: no NVD, no lookups.
			r.track("CVE.org", cveOrgErr)
			nvdComplete = cveOrgErr == nil
		}
	} else if r.st.NVDCursor.Before(r.st.NVDPolled) {
		r.problem("last NVD check did not finish; it is retried at the next NVD poll")
	}

	kevOK := r.deliver("ACT NOW: actively exploited", kevAlerts)
	nvdOK := r.deliver("New CRITICAL/HIGH CVEs", nvdAlerts)
	if !kevOK || !nvdOK {
		r.problem("some alerts were not delivered; they are retried")
	}
	if nvdComplete && nvdOK {
		r.st.NVDCursor = r.now
	}
	return r.res
}

// nvdDue reports whether NVDMinGap has passed since the last poll. A poll
// time in the future is bad data, not a recent poll.
func (r *run) nvdDue() bool {
	last := r.st.NVDPolled
	d := r.now.Sub(last)
	return last.IsZero() || d < 0 || d >= NVDMinGap
}

func (r *run) problem(msg string) { r.res.Problems = append(r.res.Problems, msg) }

// track records err for name, and messages when name starts or stops failing.
func (r *run) track(name string, err error) {
	if err != nil {
		r.problem(name + ": " + err.Error())
	}
	_, was := r.st.Broken[name]
	switch {
	case err != nil && !was:
		msg := notify.Message{
			Title:  "message-me-cve: cannot check " + name,
			Body:   name + " is failing. You are NOT covered until this clears.\n" + err.Error(),
			Urgent: true,
		}
		if r.send(msg) {
			r.st.Broken[name] = err.Error()
		}
	case err == nil && was:
		msg := notify.Message{Title: "message-me-cve: " + name + " OK again", Body: name + " is working again."}
		if r.send(msg) {
			delete(r.st.Broken, name)
		}
	}
}

// alert is one CVE to message, with every profile it concerns.
type alert struct {
	key      string // "kev:CVE-..." or "nvd:CVE-..."
	profiles []string
	words    []string
	kev      *feed.KEVEntry
	cve      *feed.CVE
	cveOrg   bool // NVD match came from the CVE.org record
}

// alertSet groups matches by key, in first-seen order.
type alertSet struct {
	list  []*alert
	byKey map[string]*alert
}

func (s *alertSet) add(key, profile, word string) *alert {
	if s.byKey == nil {
		s.byKey = map[string]*alert{}
	}
	a := s.byKey[key]
	if a == nil {
		a = &alert{key: key}
		s.byKey[key] = a
		s.list = append(s.list, a)
	}
	if !slices.Contains(a.profiles, profile) {
		a.profiles = append(a.profiles, profile)
	}
	if !slices.Contains(a.words, word) {
		a.words = append(a.words, word)
	}
	return a
}

func (r *run) matchKEV(kev []feed.KEVEntry, profiles []Profile) []*alert {
	var set alertSet
	for i := range kev {
		e := &kev[i]
		key := "kev:" + e.CveID
		for _, p := range profiles {
			if w := match.KEV(*e, p.Words); w != "" && !r.st.WasSent(p.Name, key) {
				set.add(key, p.Name, w).kev = e
			}
		}
	}
	return set.list
}

// matchNVD returns alerts for recent CRITICAL/HIGH CVEs. A CVE already sent,
// or about to be sent, as KEV for a profile is not sent again as NVD. A
// CVE.org failure holds back only the CVE that needed the lookup.
func (r *run) matchNVD(cves []feed.CVE, profiles []Profile, kevAlerts []*alert) ([]*alert, error) {
	pendingKEV := map[string]bool{}
	for _, a := range kevAlerts {
		for _, p := range a.profiles {
			pendingKEV[p+" "+a.key] = true
		}
	}
	var set alertSet
	var cveOrgErr error
	for i := range cves {
		c := &cves[i]
		if sev, _, _ := c.Severity(); sev != "CRITICAL" && sev != "HIGH" {
			continue
		}
		// Unparseable date: keep the CVE rather than drop it silently.
		if p, err := c.PublishedAt(); err == nil && r.now.Sub(p) > nvdMaxAge {
			continue
		}
		key, kevKey := "nvd:"+c.ID, "kev:"+c.ID
		for _, p := range profiles {
			if r.st.WasSent(p.Name, key) || r.st.WasSent(p.Name, kevKey) || pendingKEV[p.Name+" "+kevKey] {
				continue
			}
			w, confirmed, err := match.NVD(r.ctx, *c, p.Words, r.lookup)
			if err != nil {
				cveOrgErr = err
				continue
			}
			if w != "" {
				a := set.add(key, p.Name, w)
				a.cve, a.cveOrg = c, !confirmed
			}
		}
	}
	return set.list, cveOrgErr
}

func (r *run) lookup(ctx context.Context, id string) ([]string, error) {
	if res, ok := r.affected[id]; ok {
		return res.products, res.err
	}
	products, err := r.Feeds.Affected(ctx, id)
	r.affected[id] = affectedResult{products, err}
	return products, err
}

// deliver sends alerts, one message each, or as a combined list when there
// are many (a new watch word can match years of KEV history). Returns false
// if any message was not delivered.
func (r *run) deliver(listTitle string, alerts []*alert) bool {
	for _, a := range alerts {
		for _, p := range a.profiles {
			r.reports[p].New++
		}
	}
	if len(alerts) <= maxSingle {
		ok := true
		for _, a := range alerts {
			if r.send(a.message()) {
				r.markSent(a)
			} else {
				ok = false
			}
		}
		return ok
	}
	urgent := alerts[0].kev != nil
	ok, part := true, 1
	for _, chunk := range chunks(alerts) {
		lines := make([]string, len(chunk))
		for i, a := range chunk {
			lines[i] = a.short()
		}
		msg := notify.Message{
			Title:  fmt.Sprintf("%s: %d matches (part %d)", listTitle, len(alerts), part),
			Body:   strings.Join(lines, "\n"),
			Urgent: urgent,
		}
		if r.send(msg) {
			for _, a := range chunk {
				r.markSent(a)
			}
		} else {
			ok = false
		}
		part++
	}
	return ok
}

// chunks splits alerts into groups whose short lines fit in maxBody.
func chunks(alerts []*alert) [][]*alert {
	var out [][]*alert
	var chunk []*alert
	size := 0
	for _, a := range alerts {
		n := len(a.short()) + 1
		if size+n > maxBody && len(chunk) > 0 {
			out = append(out, chunk)
			chunk, size = nil, 0
		}
		chunk = append(chunk, a)
		size += n
	}
	return append(out, chunk)
}

func (r *run) markSent(a *alert) {
	if r.DryRun {
		return
	}
	for _, p := range a.profiles {
		r.st.MarkSent(p, a.key, r.now)
		r.reports[p].Sent++
	}
}

// send delivers m to every channel. It reports success only if all of them
// accepted it.
func (r *run) send(m notify.Message) bool {
	d := Delivery{At: time.Now().UTC(), Message: m, OK: true}
	if r.DryRun {
		d.Results = []string{"dry run, not sent"}
	} else {
		for _, s := range r.Senders {
			if err := s.Send(r.ctx, m); err != nil {
				d.OK = false
				d.Results = append(d.Results, s.Name()+": "+err.Error())
			} else {
				d.Results = append(d.Results, s.Name()+": delivered")
			}
		}
	}
	r.res.Deliveries = append(r.res.Deliveries, d)
	level := slog.LevelInfo
	if !d.OK {
		level = slog.LevelError
	}
	r.Log.Log(r.ctx, level, "message", "title", m.Title, "delivery", strings.Join(d.Results, "; "))
	return d.OK
}
