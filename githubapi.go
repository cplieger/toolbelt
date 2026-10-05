package toolbelt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// githubAPIHost is the only origin the GitHub credential is ever sent to.
const githubAPIHost = "api.github.com"

const (
	// rateLimitBodyCap bounds how much of a 403 or 429 body is read.
	rateLimitBodyCap = 64 << 10
	// secondaryLimitPhrase is what GitHub's secondary-limit refusal says.
	secondaryLimitPhrase = "secondary rate limit"
	// minRateLimitWait is GitHub's advised wait after a rate-limit refusal
	// that names no later time.
	minRateLimitWait = time.Minute
)

// githubAPITransport owns every api.github.com request the engine makes: it
// asks token (Config.GitHubToken) for the credential on those requests and no
// others, so a token cannot reach a download host, and it reports a rate-limit
// refusal as a *GitHubRateLimitError instead of a bare 403 or 429.
type githubAPITransport struct {
	next   http.RoundTripper
	token  func(context.Context) (string, error)
	limits *rateLimitGate
}

// rateLimitGate holds each credential's last rate-limit refusal until it
// lapses, so the transport refuses locally instead of sending what GitHub
// would refuse: continuing to send while limited can get an integration
// banned (rateLimitFrom's link, "Exceeding the rate limit").
type rateLimitGate struct {
	held map[[sha256.Size]byte]heldRefusal
	mu   sync.Mutex
}

type heldRefusal struct {
	until time.Time
	err   GitHubRateLimitError
}

// refusal returns a copy of the refusal held for key at now, or nil.
func (g *rateLimitGate) refusal(key [sha256.Size]byte, now time.Time) *GitHubRateLimitError {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, ok := g.held[key]
	if !ok || !now.Before(h.until) {
		return nil
	}
	rl := h.err
	return &rl
}

// record holds rl for key until its Reset, and for at least minRateLimitWait,
// so a reset already past by the local clock cannot open a request burst.
func (g *rateLimitGate) record(key [sha256.Size]byte, rl *GitHubRateLimitError, now time.Time) {
	until := now.Add(minRateLimitWait)
	if rl.Reset.After(until) {
		until = rl.Reset
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	maps.DeleteFunc(g.held, func(_ [sha256.Size]byte, h heldRefusal) bool { return !now.Before(h.until) })
	if g.held == nil {
		g.held = map[[sha256.Size]byte]heldRefusal{}
	}
	g.held[key] = heldRefusal{until: until, err: *rl}
}

func (t githubAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() != githubAPIHost {
		return t.next.RoundTrip(req)
	}
	tok := ""
	if t.token != nil {
		var err error
		if tok, err = t.token(req.Context()); err != nil {
			closeRequestBody(req)
			return nil, fmt.Errorf("github token: %w", err)
		}
	}
	// A digest, so the gate never holds the token itself.
	key := sha256.Sum256([]byte(tok))
	if rl := t.limits.refusal(key, time.Now()); rl != nil {
		closeRequestBody(req)
		return nil, rl
	}
	if tok != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if rl := rateLimitFrom(resp, tok != "", now); rl != nil {
		t.limits.record(key, rl, now)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, rateLimitBodyCap))
		_ = resp.Body.Close()
		return nil, rl
	}
	return resp, nil
}

// closeRequestBody closes req's body on a path that never sends it:
// RoundTrip owns the body on every path (http.RoundTripper).
func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// rateLimitFrom classifies a 403 or 429 by GitHub's rules: X-RateLimit-Remaining
// 0 is the primary quota; Retry-After, or a body naming a secondary rate limit,
// is the secondary one, which can arrive with remaining 0 too. Any other 403
// returns nil with resp's body intact.
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit
func rateLimitFrom(resp *http.Response, authenticated bool, now time.Time) *GitHubRateLimitError {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return nil
	}
	primary := resp.Header.Get("X-RateLimit-Remaining") == "0"
	retryAt, hasRetryAfter := retryAfter(resp.Header.Get("Retry-After"), now)
	secondary := hasRetryAfter || bodyNamesSecondaryLimit(resp)
	if !primary && !secondary {
		return nil
	}
	rl := &GitHubRateLimitError{Authenticated: authenticated, Secondary: secondary}
	if n, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit")); err == nil && n > 0 {
		rl.Limit = n
	}
	if secs, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); primary && err == nil && secs > 0 {
		rl.Reset = time.Unix(secs, 0).UTC()
	}
	if hasRetryAfter && retryAt.After(rl.Reset) {
		rl.Reset = retryAt
	}
	if rl.Reset.IsZero() && secondary {
		rl.Reset = now.Add(minRateLimitWait).UTC()
	}
	return rl
}

// retryAfter reads a Retry-After value, delay-seconds or an HTTP-date
// (RFC 9110 section 10.2.3).
func retryAfter(v string, now time.Time) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs >= 0 && secs <= math.MaxInt64/int64(time.Second) {
		return now.Add(time.Duration(secs) * time.Second).UTC(), true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// replayBody serves the bytes already read from a body ahead of the rest.
type replayBody struct {
	io.Reader
	io.Closer
}

// bodyNamesSecondaryLimit reports whether resp's body names a secondary rate
// limit, leaving resp.Body readable from its first byte.
func bodyNamesSecondaryLimit(resp *http.Response) bool {
	head, err := io.ReadAll(io.LimitReader(resp.Body, rateLimitBodyCap))
	resp.Body = replayBody{Reader: io.MultiReader(bytes.NewReader(head), resp.Body), Closer: resp.Body}
	if err != nil {
		return false
	}
	return bytes.Contains(bytes.ToLower(head), []byte(secondaryLimitPhrase))
}

// ErrGitHubRateLimited classifies a request GitHub's API refused for a rate
// limit. errors.As with a *GitHubRateLimitError (the pointer) reads the
// detail; Add, EnsureInstalled and a failed Job's Err return it wrapped.
var ErrGitHubRateLimited = errors.New("GitHub API rate limit reached")

// GitHubRateLimitError is the ErrGitHubRateLimited shape. The engine
// neither retries nor waits on it. Until Reset, and for at least a minute,
// a GitHub API request with the refused credential (the same token, or no
// token after an anonymous refusal) gets a copy of it without being sent.
type GitHubRateLimitError struct {
	// Reset is the earliest time GitHub allows another request: a minute
	// after the refusal for a secondary limit that names no time, zero
	// for a primary one that names none.
	Reset time.Time
	// Limit is the X-RateLimit-Limit quota, 0 when GitHub did not send it.
	Limit int
	// Authenticated reports whether the refused request carried a token.
	Authenticated bool
	// Secondary marks GitHub's secondary (abuse) limit, not the hourly quota.
	Secondary bool
}

func (e *GitHubRateLimitError) Error() string {
	limit := "rate limit"
	if e.Secondary {
		limit = "secondary rate limit"
	}
	when := ""
	if !e.Reset.IsZero() {
		when = ", resets at " + e.Reset.Format("15:04 MST")
	}
	if e.Authenticated {
		return "GitHub API " + limit + " reached for this token" + when
	}
	return "GitHub API " + limit + " reached for unauthenticated requests" + when +
		". Configure a GitHub token for the tools engine to raise the limit"
}

// Is makes errors.Is(err, ErrGitHubRateLimited) match.
func (e *GitHubRateLimitError) Is(target error) bool { return target == ErrGitHubRateLimited }

// Wire returns e in the form Job.RateLimit carries.
func (e *GitHubRateLimitError) Wire() GitHubRateLimit {
	w := GitHubRateLimit{Limit: e.Limit, Authenticated: e.Authenticated, Secondary: e.Secondary}
	if !e.Reset.IsZero() {
		w.ResetAt = e.Reset.UnixMilli()
	}
	return w
}
