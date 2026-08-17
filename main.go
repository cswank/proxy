package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const (
	// tlsLogInterval is how often a TLS handshake error is allowed through to
	// the log. Scanners generate these continuously, but dropping them all
	// hides real certificate and downgrade problems.
	tlsLogInterval = time.Minute

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

type (
	host string

	config struct {
		Cert    string          `envconfig:"CERT" required:"true"`
		Key     string          `envconfig:"KEY" required:"true"`
		Port    string          `envconfig:"PORT" default:":8000"`
		Map     map[string]host `envconfig:"MAP" required:"true"`
		WWW     string          `envconfig:"WWW" default:"/home/proxy/www"`
		Verbose bool            `envconfig:"VERBOSE" default:"false"`
	}
)

func (h *host) Decode(value string) error {
	s, err := url.QueryUnescape(value)
	*h = host(s)
	return err
}

// filterWriter rate-limits noisy TLS-handshake scanner errors from the http
// server's log while passing everything else through to the standard logger.
// It expects to back a log.Logger with no flags of its own: every line is
// re-emitted through log.Print, which supplies the one and only timestamp.
type filterWriter struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (f *filterWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if !strings.Contains(msg, "TLS handshake error") {
		log.Print(msg)
		return len(p), nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	if !f.last.IsZero() && now.Sub(f.last) < tlsLogInterval {
		f.suppressed++
		return len(p), nil
	}

	if f.suppressed > 0 {
		msg = fmt.Sprintf("%s (+%d suppressed in the last %s)", msg, f.suppressed, tlsLogInterval)
	}
	f.last, f.suppressed = now, 0
	log.Print(msg)
	return len(p), nil
}

// statusRecorder wraps http.ResponseWriter to capture the response status code
// for access logging. It forwards Flush and Hijack so streaming responses and
// websocket upgrades through the reverse proxy keep working.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// backupSuffixes are editor and tool leftovers, which get written in place
// right next to the file they shadow. index.html~ serves the previous revision
// of a page as plain text, so scanners probe for these alongside .git and .env.
var backupSuffixes = []string{"~", ".bak", ".orig", ".old", ".save", ".swp", ".swo", ".rej"}

// blocked reports whether p must not be served, either because a path segment
// is dot-prefixed (/licks/.git/config, /.env) or because one is an editor
// backup (/index.html~, /band/song.css~). /.well-known is exempt so ACME
// challenges and friends keep working.
func blocked(p string) bool {
	for _, seg := range strings.Split(path.Clean("/"+strings.TrimPrefix(p, "/")), "/") {
		if len(seg) > 1 && seg[0] == '.' && seg != ".well-known" {
			return true
		}
		if backup(seg) {
			return true
		}
	}
	return false
}

// backup reports whether a single path segment names an editor backup. It is
// checked per segment rather than on the basename alone so that a whole
// leftover directory, foo.orig/bar.txt, is covered too.
func backup(seg string) bool {
	seg = strings.ToLower(seg)
	for _, suffix := range backupSuffixes {
		if len(seg) > len(suffix) && strings.HasSuffix(seg, suffix) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases a Host header and strips any port, so that
// "Example.COM", "example.com" and "example.com:8000" all route alike.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if hostname, _, err := net.SplitHostPort(h); err == nil {
		h = hostname
	}
	return strings.Trim(h, "[]")
}

// notFoundFS reports any failure to resolve a name that isn't a permission
// problem — including os.Root refusing a symlink that leaves the tree — as
// "not found". Without it those refusals reach http.FileServerFS as unknown
// errors and become a 500, which both leaks that something is there and
// buries a routine block in error logs.
type notFoundFS struct{ fs.FS }

func (n notFoundFS) Open(name string) (fs.File, error) {
	f, err := n.FS.Open(name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return f, err
}

// staticFiles serves a directory tree without generating directory listings
// and without following symlinks out of the tree. os.Root gives us the latter;
// http.Dir does not.
//
// Note that os.Root rejects *absolute* symlinks even when they point back
// inside the tree; symlinks within the web root have to be relative.
type staticFiles struct {
	fsys fs.FS
	h    http.Handler
}

func newStaticFiles(dir string) (*staticFiles, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	fsys := notFoundFS{root.FS()}
	return &staticFiles{fsys: fsys, h: http.FileServerFS(fsys)}, nil
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if s.listing(req.URL.Path) {
		http.NotFound(w, req)
		return
	}
	s.h.ServeHTTP(w, req)
}

// listing reports whether p names a directory with no index.html, which is
// what http.FileServer would answer with an auto-generated index of the tree.
func (s *staticFiles) listing(p string) bool {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "/")), "/")
	if name == "" {
		name = "."
	}
	fi, err := fs.Stat(s.fsys, name)
	if err != nil || !fi.IsDir() {
		return false
	}
	_, err = fs.Stat(s.fsys, path.Join(name, "index.html"))
	return err != nil
}

// newProxy builds a reverse proxy to target. Unlike
// httputil.NewSingleHostReverseProxy it replaces the client's X-Forwarded-*
// headers instead of letting them through, so a backend that trusts them
// cannot be fed a forged client IP or scheme.
func newProxy(target *url.URL) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// SetXForwarded appends to any X-Forwarded-For it finds, so the
			// client-supplied one has to go first. X-Forwarded-Host and
			// -Proto it overwrites, but X-Real-IP and Forwarded are ours to
			// clear.
			r.Out.Header.Del("X-Forwarded-For")
			r.Out.Header.Del("X-Real-Ip")
			r.Out.Header.Del("Forwarded")
			r.SetXForwarded()

			r.SetURL(target)
			// SetURL blanks Host, which would send the backend its own name.
			// Keep forwarding the client's, as the old Director-based proxy did.
			r.Out.Host = r.In.Host
		},
	}
}

// server routes by Host header: a configured backend if there is one for the
// host, the static file tree otherwise.
type server struct {
	proxies map[string]http.Handler
	static  http.Handler
	verbose bool
}

func newServer(cfg config) (*server, error) {
	static, err := newStaticFiles(cfg.WWW)
	if err != nil {
		return nil, fmt.Errorf("unable to serve www dir %s: %w", cfg.WWW, err)
	}

	proxies := make(map[string]http.Handler, len(cfg.Map))
	for h, target := range cfg.Map {
		u, err := url.Parse(string(target))
		if err != nil {
			return nil, fmt.Errorf("invalid target %q for host %s: %w", target, h, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("target %q for host %s needs a scheme and a host", target, h)
		}
		proxies[normalizeHost(h)] = newProxy(u)
	}

	return &server{proxies: proxies, static: static, verbose: cfg.Verbose}, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if blocked(req.URL.Path) {
		http.NotFound(w, req)
		return
	}

	p, ok := s.proxies[normalizeHost(req.Host)]
	if !ok {
		s.static.ServeHTTP(w, req)
		return
	}

	if s.verbose {
		// Named fields only: %+v on the request would put Authorization
		// headers and session cookies in the log.
		log.Printf("proxying %s%s ua=%q referer=%q len=%d",
			req.Host, req.URL.RequestURI(), req.UserAgent(), req.Referer(), req.ContentLength)
	}

	p.ServeHTTP(w, req)
}

// logRequests wraps h and logs one line per completed request.
func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		h.ServeHTTP(rec, req)
		log.Printf("%s %s %q %d %s", req.RemoteAddr, req.Method, req.Host+req.URL.RequestURI(), rec.status, time.Since(start))
	})
}

func main() {
	var cfg config
	if err := envconfig.Process("PROXY", &cfg); err != nil {
		log.Fatal("unable to parse config ", err.Error())
	}

	s, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", cfg.Port)

	srv := &http.Server{
		Addr:     cfg.Port,
		Handler:  logRequests(s),
		ErrorLog: log.New(&filterWriter{}, "", 0),

		// Without these a handful of trickled requests pin goroutines
		// indefinitely. WriteTimeout stays off: we forward Hijack for
		// websockets, which have no bounded response time.
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
	}
	if err := srv.ListenAndServeTLS(cfg.Cert, cfg.Key); err != nil {
		log.Fatal(err)
	}
}
