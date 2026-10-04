package toolbelt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// githubAPIHost is the only origin the GitHub credential is ever sent to.
const githubAPIHost = "api.github.com"

type githubTokenCache struct {
	checked time.Time
	// token caches the gh auth token lookup. Successes cache forever; an
	// empty result is retried after ghTokenRetry so a forge login
	// performed after boot is picked up.
	token string
	mu    sync.Mutex
}

const ghTokenRetry = time.Minute

// Token returns a GitHub API token when one is discoverable: the gh CLI's
// stored token, which gh also reads from GH_TOKEN or GITHUB_TOKEN. Failure is
// fine: calls proceed anonymously, and a lookup after ghTokenRetry retries.
func (c *githubTokenCache) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" || time.Since(c.checked) < ghTokenRetry {
		return c.token
	}
	c.checked = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A bare name on purpose: this engine installs gh into its own bin/, so a
	// systemCommand pin would break forge auth and confine nothing.
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err == nil {
		c.token = strings.TrimSpace(string(out))
	}
	return c.token
}

// githubAPITransport owns every api.github.com request the engine makes: it
// attaches the credential to those requests and no others, so a token cannot
// reach a download host, and it reports an exhausted rate limit as a
// *githubRateLimitError instead of a bare 403.
type githubAPITransport struct {
	next   http.RoundTripper
	tokens *githubTokenCache
}

func (t githubAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() != githubAPIHost {
		return t.next.RoundTrip(req)
	}
	tok := ""
	if t.tokens != nil {
		tok = t.tokens.Token()
	}
	if tok != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if rl := rateLimitFrom(resp, tok != ""); rl != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		return nil, rl
	}
	return resp, nil
}

// rateLimitFrom reads GitHub's primary rate-limit verdict off a response:
// 403 or 429 with X-RateLimit-Remaining 0. Any other 403 (a private repository,
// a secondary limit) is left for the caller to report as a status error.
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
func rateLimitFrom(resp *http.Response, authenticated bool) *githubRateLimitError {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return nil
	}
	if resp.Header.Get("X-RateLimit-Remaining") != "0" {
		return nil
	}
	rl := &githubRateLimitError{authenticated: authenticated}
	if secs, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && secs > 0 {
		rl.reset = time.Unix(secs, 0).UTC()
	}
	return rl
}

// githubRateLimitError reports an exhausted GitHub API quota. It is not
// transient: the quota is hourly, far beyond any retry budget here.
type githubRateLimitError struct {
	reset         time.Time
	authenticated bool
}

func (e *githubRateLimitError) Error() string {
	when := ""
	if !e.reset.IsZero() {
		when = ", resets at " + e.reset.Format("15:04 MST")
	}
	if e.authenticated {
		return fmt.Sprintf("GitHub API rate limit reached for this token%s", when)
	}
	return fmt.Sprintf("GitHub API rate limit reached for unauthenticated requests%s. "+
		"Install the gh CLI and run gh auth login, or set GH_TOKEN for gh, to raise the limit", when)
}
