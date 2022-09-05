package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/kelseyhightower/envconfig"
)

var cfg config

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

func main() {
	err := envconfig.Process("PROXY", &cfg)
	if err != nil {
		log.Fatal("unable to parse config ", err.Error())
	}

	log.Printf("listening on %s", cfg.Port)
	if err := http.ListenAndServeTLS(cfg.Port, cfg.Cert, cfg.Key, http.HandlerFunc(handleRequestAndRedirect)); err != nil {
		log.Fatal(err)
	}
}

func handleRequestAndRedirect(w http.ResponseWriter, req *http.Request) {
	h, ok := cfg.Map[req.Host]
	if !ok {
		http.FileServer(http.Dir(cfg.WWW)).ServeHTTP(w, req)
		return
	}

	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	if cfg.Verbose {
		log.Printf("%+v", req)
	}

	url, err := url.Parse(string(h))
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	httputil.NewSingleHostReverseProxy(url).ServeHTTP(w, req)
}
