package toolbelt

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cplieger/httpx/v5"
)

// githubTokenCache memoizes the gh-token lookup for every GitHub API call
// this library makes.
//
// It is shared rather than per-caller because the rate limit is: the
// anonymous ceiling is 60 requests an hour for the whole process, and a
// release install spends two of them on one tool — one resolving the tag,
// one listing the assets. An earlier draft gave the version resolver the
// token and left the asset listing anonymous, which failed exactly the way
// that arithmetic predicts: the tag resolved and the listing came back
// HTTP 403 on a repository whose release was public.
type githubTokenCache struct {
	checked time.Time
	// token caches the gh auth token lookup. Successes cache forever; an
	// empty result is retried after ghTokenRetry so a forge login
	// performed after boot is picked up.
	token string
	mu    sync.Mutex
}

// ghTokenRetry is how long an empty gh-token probe result is trusted.
const ghTokenRetry = time.Minute

// Token returns a GitHub API token when one is discoverable: the gh CLI's
// stored token (a forge login flow provisions it). Failure is fine — calls
// proceed anonymously and the caller retries later.
func (c *githubTokenCache) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" || time.Since(c.checked) < ghTokenRetry {
		return c.token
	}
	c.checked = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err == nil {
		c.token = strings.TrimSpace(string(out))
	}
	return c.token
}

// githubAuth returns the httpx options that authenticate a request when
// the URL is the GitHub API and a token is available. Any other host gets
// nothing: the token must not travel to a download URL, which is a
// different origin and needs no credential to read a public release.
func githubAuth(rawURL string, tokens *githubTokenCache) []httpx.GetOption {
	if tokens == nil || !strings.HasPrefix(rawURL, "https://api.github.com/") {
		return nil
	}
	tok := tokens.Token()
	if tok == "" {
		return nil
	}
	return []httpx.GetOption{httpx.WithHeaders(func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tok)
	})}
}
