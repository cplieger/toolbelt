package toolbelt

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/httpx/v5"
)

func githubTestClient(srv *httptest.Server, tokens *githubTokenCache) *http.Client {
	return &http.Client{Transport: githubAPITransport{next: srv.Client().Transport, tokens: tokens}}
}

type authLog struct {
	got map[string]string
	mu  sync.Mutex
}

func (a *authLog) record(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got[r.Host+r.URL.Path] = r.Header.Get("Authorization")
}

func (a *authLog) header(hostPath string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.got[hostPath]
	return h, ok
}

func TestGitHubAPITransport_TokenReachesOnlyTheAPI(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{name: "a token the gh CLI produces is attached", script: "echo tok-abc", want: "Bearer tok-abc"},
		{name: "no token means no header at all", script: "exit 1", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)

			auth := &authLog{got: map[string]string{}}
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth.record(r)
				switch r.URL.Path {
				case "/repos/o/r/releases/latest":
					fmt.Fprint(w, `{"tag_name":"v1.0.0"}`)
				case "/repos/o/r/releases/tags/v1.0.0":
					fmt.Fprint(w, `{"assets":[{"name":"r-linux-amd64"}]}`)
				case "/repos/o/r/moved":
					http.Redirect(w, r, "https://objects.githubusercontent.com/asset.json", http.StatusFound)
				default:
					fmt.Fprint(w, `{}`)
				}
			}))
			client := githubTestClient(srv, &githubTokenCache{})
			v := newTestVersionResolver(client)
			in := &installer{client: client, output: func(string) {}}
			rr := releaseRef{Host: releaseHostGitHub, Owner: "o", Repo: "r"}

			if _, err := v.Latest(t.Context(), "release:github/o/r", nil); err != nil {
				t.Fatalf("Latest(release:github/o/r) = %v", err)
			}
			if _, err := in.listReleaseAssets(t.Context(), rr, "v1.0.0"); err != nil {
				t.Fatalf("listReleaseAssets(o/r v1.0.0) = %v", err)
			}
			var doc struct{}
			if err := fetchJSON(t.Context(), client, releaseDownloadURL(rr, "v1.0.0", "r.json"), 1<<10, &doc); err != nil {
				t.Fatalf("fetchJSON(download URL) = %v", err)
			}
			if err := fetchJSON(t.Context(), client, "https://api.github.com/repos/o/r/moved", 1<<10, &doc); err != nil {
				t.Fatalf("fetchJSON(redirecting API URL) = %v", err)
			}

			for _, hostPath := range []string{
				"api.github.com/repos/o/r/releases/latest",
				"api.github.com/repos/o/r/releases/tags/v1.0.0",
				"api.github.com/repos/o/r/moved",
			} {
				if got, ok := auth.header(hostPath); !ok || got != tc.want {
					t.Errorf("%s: Authorization = %q (seen %v), want %q", hostPath, got, ok, tc.want)
				}
			}
			for _, hostPath := range []string{
				"github.com/o/r/releases/download/v1.0.0/r.json",
				"objects.githubusercontent.com/asset.json",
			} {
				if got, ok := auth.header(hostPath); !ok || got != "" {
					t.Errorf("%s: Authorization = %q (seen %v), want none: the token must not leave the API host", hostPath, got, ok)
				}
			}
		})
	}
}

func TestGitHubAPITransport_ExhaustedQuotaIsANamedError(t *testing.T) {
	reset := time.Date(2026, 10, 4, 14, 5, 0, 0, time.UTC)
	cases := []struct {
		name     string
		token    string
		status   int
		resetHdr string
		want     []string
		notWant  []string
	}{
		{
			name: "403 anonymous", status: http.StatusForbidden, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want:    []string{"rate limit", "unauthenticated", "resets at 14:05 UTC", "Install the gh CLI", "gh auth login", "GH_TOKEN"},
			notWant: []string{"api.github.com", "https://"},
		},
		{
			name: "429 anonymous", status: http.StatusTooManyRequests, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want: []string{"rate limit", "resets at 14:05 UTC"},
		},
		{
			name: "403 with a token", token: "tok", status: http.StatusForbidden, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want:    []string{"rate limit reached for this token", "resets at 14:05 UTC"},
			notWant: []string{"gh auth login"},
		},
		{
			name: "no reset header", status: http.StatusForbidden,
			want:    []string{"rate limit"},
			notWant: []string{"resets at"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.Header().Set("X-RateLimit-Remaining", "0")
				if tc.resetHdr != "" {
					w.Header().Set("X-RateLimit-Reset", tc.resetHdr)
				}
				w.WriteHeader(tc.status)
			}))
			tokens := &githubTokenCache{token: tc.token, checked: time.Now()}
			v := newTestVersionResolver(githubTestClient(srv, tokens))

			_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
			if _, ok := errors.AsType[*githubRateLimitError](err); !ok {
				t.Fatalf("Latest(aqua:owner/repo) = %v (%T), want a *githubRateLimitError", err, err)
			}
			if requests != 1 {
				t.Errorf("Latest(aqua:owner/repo) made %d requests, want 1: an exhausted quota is not retried", requests)
			}
			msg := err.Error()
			for _, s := range tc.want {
				if !strings.Contains(msg, s) {
					t.Errorf("error %q does not contain %q", msg, s)
				}
			}
			for _, s := range tc.notWant {
				if strings.Contains(msg, s) {
					t.Errorf("error %q contains %q", msg, s)
				}
			}
		})
	}
}

func TestGitHubAPITransport_ReleaseListingReportsTheRateLimit(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	in := &installer{client: githubTestClient(srv, &githubTokenCache{checked: time.Now()}), output: func(string) {}}

	_, err := in.listReleaseAssets(t.Context(), releaseRef{Host: releaseHostGitHub, Owner: "o", Repo: "r"}, "v1")
	if _, ok := errors.AsType[*githubRateLimitError](err); !ok {
		t.Fatalf("listReleaseAssets(o/r v1) = %v (%T), want a *githubRateLimitError", err, err)
	}
}

func TestGitHubAPITransport_OtherForbiddenPassesThrough(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "42")
		w.WriteHeader(http.StatusForbidden)
	}))
	v := newTestVersionResolver(githubTestClient(srv, &githubTokenCache{checked: time.Now()}))

	_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
	se, ok := errors.AsType[*httpx.StatusError](err)
	if !ok || se.Code != http.StatusForbidden {
		t.Fatalf("Latest(aqua:owner/repo) = %v (%T), want an *httpx.StatusError with code 403", err, err)
	}
	if _, ok := errors.AsType[*githubRateLimitError](err); ok {
		t.Errorf("Latest(aqua:owner/repo) = %v, classified as a rate limit with quota remaining", err)
	}
}
