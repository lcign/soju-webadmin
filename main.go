package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		listen   = flag.String("listen", "127.0.0.1:8080", "address to serve on")
		sojuAddr = flag.String("soju", "localhost:6697", "soju address, host:port")
		noTLS    = flag.Bool("soju-plaintext", false, "talk to soju without TLS (only sane over loopback)")
		insecure = flag.Bool("soju-insecure", false, "accept soju's certificate without verifying it")
		basePath = flag.String("base-path", "", "serve under a sub-path, e.g. /soju")
		certFile = flag.String("tls-cert", "", "certificate for serving HTTPS directly")
		keyFile  = flag.String("tls-key", "", "private key for serving HTTPS directly")
		secureCk = flag.Bool("secure-cookie", false, "mark the session cookie Secure (set this behind an HTTPS proxy)")
		idle     = flag.Duration("idle-timeout", time.Hour, "close a session after this long without a request")

		watch      = flag.Bool("watch", false, "run the watcher instead of the web interface")
		watchOnce  = flag.Bool("watch-once", false, "with -watch, do a single pass and exit (for a systemd timer or cron)")
		watchDry   = flag.Bool("watch-dry-run", false, "with -watch, report what it would do and change nothing")
		watchConf  = flag.String("watch-config", "/etc/soju-webadmin/watch.conf", "configuration for -watch")
		watchState = flag.String("watch-state-dir", "/var/lib/soju-webadmin", "where -watch keeps its per-network state")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "soju-webadmin — a web interface for the soju IRC bouncer\n\nusage: %s [options]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nUsers sign in with their soju credentials; this program keeps no accounts\nand no database of its own.\n")
	}
	flag.Parse()

	prefix := strings.TrimSuffix(*basePath, "/")
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}

	cfg := ServerConfig{Addr: *sojuAddr, TLS: !*noTLS, Insecure: *insecure}

	if *watch {
		conf, err := LoadConfig(*watchConf)
		if err != nil {
			log.Fatal(err)
		}
		w, err := NewWatcher(cfg, conf, *watchState, *watchDry)
		if err != nil {
			log.Fatal(err)
		}
		if *watchOnce {
			if err := w.Run(); err != nil {
				log.Fatal(err)
			}
			return
		}
		log.Printf("watching soju at %s every %s", cfg.Addr, w.interval)
		w.RunForever()
		return
	}

	srv, err := NewServer(cfg, NewSessionStore(*idle), prefix, *secureCk || *certFile != "")
	if err != nil {
		log.Fatal(err)
	}

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	scheme := "http"
	if *certFile != "" {
		scheme = "https"
	}
	log.Printf("soju at %s (tls=%v), serving on %s://%s%s/", cfg.Addr, cfg.TLS, scheme, *listen, prefix)

	if *certFile != "" {
		err = hs.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = hs.ListenAndServe()
	}
	log.Fatal(err)
}
