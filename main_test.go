package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlocked(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/licks/.git/config", true},
		{"/.git/config", true},
		{"/.env", true},
		{"/.git", true},
		{"/a/b/.ssh/", true},
		{"/a/%2e%2e/.git/config", true}, // req.URL.Path is already unescaped
		{"/.well-known/acme-challenge/token", false},
		{"/", false},
		{"/licks/index.html", false},
		{"/licks/foo.min.js", false},
		{"/a./b", false},

		// Editor backups actually present in the web root.
		{"/index.html~", true},
		{"/boots.html~", true},
		{"/page.html~", true},
		{"/iremitter.html~", true},
		{"/ir_emitter_circuit.svg~", true},
		{"/band/song.css~", true},
		{"/band/ceruleanblue/index.html~", true},
		{"/bluetooth/index.html~", true},
		{"/webtrek/index.html~", true},

		// Other backup conventions, including a whole leftover directory.
		{"/index.html.bak", true},
		{"/index.html.BAK", true},
		{"/main.go.orig", true},
		{"/notes.old", true},
		{"/conf.save", true},
		{"/index.html.swp", true},
		{"/site.orig/index.html", true},

		// The real files they shadow must still be served.
		{"/index.html", false},
		{"/boots.html", false},
		{"/band/song.css", false},
		{"/band/ceruleanblue/index.html", false},
		{"/ir_emitter_circuit.svg", false},

		// A bare suffix is a name, not a backup of something.
		{"/~", false},
		{"/a/~", false},
		{"/.bak", true}, // dot-prefixed, caught by the other rule

		// Left alone deliberately: not backups.
		{"/licks/README.md", false},
		{"/in-keeping.zip", false},
	} {
		if got := blocked(tc.path); got != tc.want {
			t.Errorf("blocked(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com:8000", "example.com"},
		{"EXAMPLE.com:443", "example.com"},
		{" example.com ", "example.com"},
		{"[::1]:8000", "::1"},
		{"[::1]", "::1"},
		{"", ""},
	} {
		if got := normalizeHost(tc.in); got != tc.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// newTestServer builds a server whose only backend echoes the headers it saw.
func newTestServer(t *testing.T, www string) (*server, *http.Header) {
	t.Helper()

	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seen.Set("Host", r.Host) // Host lives on the request, not in Header
	}))
	t.Cleanup(backend.Close)

	s, err := newServer(config{
		WWW: www,
		Map: map[string]host{"api.example": host(backend.URL)},
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s, &seen
}

// A client cannot forge the identity headers the backend trusts.
func TestForwardedHeadersAreReplaced(t *testing.T) {
	s, seen := newTestServer(t, t.TempDir())

	req := httptest.NewRequest("GET", "https://api.example/x", nil)
	req.Host = "api.example"
	req.RemoteAddr = "203.0.113.9:1234"
	req.TLS = &tls.ConnectionState{} // as the real TLS listener would set
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	req.Header.Set("Forwarded", "for=1.2.3.4")

	s.ServeHTTP(httptest.NewRecorder(), req)

	for _, tc := range []struct{ header, want string }{
		{"X-Forwarded-For", "203.0.113.9"}, // not "1.2.3.4, 203.0.113.9"
		{"X-Forwarded-Proto", "https"},
		{"X-Forwarded-Host", "api.example"}, // was empty before the fix
		{"X-Real-Ip", ""},
		{"Forwarded", ""},
		{"Host", "api.example"}, // the client's host, as the old proxy sent
	} {
		if got := seen.Get(tc.header); got != tc.want {
			t.Errorf("backend saw %s = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestHostRouting(t *testing.T) {
	www := t.TempDir()
	if err := os.WriteFile(filepath.Join(www, "index.html"), []byte("static"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, seen := newTestServer(t, www)

	for _, tc := range []struct {
		host    string
		proxied bool
	}{
		{"api.example", true},
		{"api.example:8000", true}, // port must not defeat the lookup
		{"API.example", true},      // nor case
		{"other.example", false},
	} {
		*seen = nil
		req := httptest.NewRequest("GET", "https://x/", nil)
		req.Host = tc.host
		req.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)

		if got := *seen != nil; got != tc.proxied {
			t.Errorf("Host %q: proxied = %v, want %v (body %q)", tc.host, got, tc.proxied, rec.Body)
		}
	}
}

func TestStaticNoDirectoryListing(t *testing.T) {
	www := t.TempDir()
	if err := os.MkdirAll(filepath.Join(www, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(www, "sub", "a.txt"), []byte("listed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(www, "withindex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(www, "withindex", "index.html"), []byte("welcome"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServer(t, www)

	for _, tc := range []struct {
		path string
		code int
		body string
	}{
		{"/sub/", http.StatusNotFound, ""},        // no index.html: no auto-index
		{"/", http.StatusNotFound, ""},            // web root included
		{"/withindex/", http.StatusOK, "welcome"}, // index.html still served
		{"/sub/a.txt", http.StatusOK, "listed"},   // files still served
	} {
		req := httptest.NewRequest("GET", "https://other.example"+tc.path, nil)
		req.Host = "other.example"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)

		if rec.Code != tc.code {
			t.Errorf("GET %s = %d, want %d", tc.path, rec.Code, tc.code)
		}
		if tc.body != "" && rec.Body.String() != tc.body {
			t.Errorf("GET %s body = %q, want %q", tc.path, rec.Body, tc.body)
		}
		if strings.Contains(rec.Body.String(), "a.txt") {
			t.Errorf("GET %s leaked a directory listing: %q", tc.path, rec.Body)
		}
	}
}

func TestStaticSymlinks(t *testing.T) {
	www, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "passwd"), []byte("ESCAPED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(www, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(www, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(www, "real", "ok.txt"), []byte("INSIDE"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Relative symlinks that stay inside the tree must keep working; os.Root
	// refuses absolute ones even when they point back inside.
	if err := os.Symlink("real", filepath.Join(www, "rel")); err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServer(t, www)

	for _, tc := range []struct {
		path string
		code int
		body string
	}{
		{"/link/passwd", http.StatusNotFound, ""}, // escape blocked, and as a 404 not a 500
		{"/rel/ok.txt", http.StatusOK, "INSIDE"},  // relative symlink inside the root
		{"/real/ok.txt", http.StatusOK, "INSIDE"}, // plain file
	} {
		req := httptest.NewRequest("GET", "https://other.example"+tc.path, nil)
		req.Host = "other.example"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)

		if rec.Code != tc.code {
			t.Errorf("GET %s = %d, want %d", tc.path, rec.Code, tc.code)
		}
		if tc.body != "" && rec.Body.String() != tc.body {
			t.Errorf("GET %s body = %q, want %q", tc.path, rec.Body, tc.body)
		}
		if strings.Contains(rec.Body.String(), "ESCAPED") {
			t.Errorf("GET %s escaped the web root: %q", tc.path, rec.Body)
		}
	}
}

func TestNewServerRejectsBadTarget(t *testing.T) {
	for name, m := range map[string]map[string]host{
		"no scheme":  {"a.example": "backend:9000"},
		"no host":    {"a.example": "http://"},
		"empty":      {"a.example": ""},
		"unparsable": {"a.example": "http://a b.example"},
	} {
		if _, err := newServer(config{WWW: t.TempDir(), Map: m}); err == nil {
			t.Errorf("%s: newServer accepted %v, want a startup error", name, m)
		}
	}
}

func TestNewServerRejectsMissingWWW(t *testing.T) {
	if _, err := newServer(config{WWW: filepath.Join(t.TempDir(), "nope"), Map: map[string]host{}}); err == nil {
		t.Error("newServer accepted a nonexistent www dir, want a startup error")
	}
}
