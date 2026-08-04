package main

// HTTP layer: routing, forms, rendering.
//
// Every page is rendered server-side; the only JavaScript is a confirmation on
// destructive buttons. That keeps the whole thing servable under a strict CSP and
// working without a build step.

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg      ServerConfig
	sessions *SessionStore
	prefix   string // base path, "" or "/soju" style, no trailing slash
	secure   bool   // mark the session cookie Secure
	tmpl     *template.Template

	// stateDir is the watcher's state directory, read-only as far as this side is
	// concerned: it is where its log and per-network state are read from.
	stateDir string
	// policyPath is the watcher's policy file. Set, and it becomes editable here;
	// the credentials live in a different file this program never touches.
	policyPath string

	// locales holds the translations of the pages' fixed text, and lang is the
	// language this instance prefers before the browser and the reader are asked.
	locales *Bundle
	lang    string
}

func NewServer(cfg ServerConfig, sessions *SessionStore, prefix string, secure bool) (*Server, error) {
	funcs := template.FuncMap{
		"hasPrefix": strings.HasPrefix,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, sessions: sessions, prefix: prefix, secure: secure, tmpl: tmpl}, nil
}

// page is what every template receives. The locale is embedded, so a template
// reaches a translation with {{.T "some.key"}} — and {{$.T ...}} inside a range.
type page struct {
	*Locale

	Title   string
	Prefix  string
	User    string
	IsAdmin bool
	CSRF    string
	Flash   *Flash
	Nav     string // which nav entry to mark as current
	Data    any
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.auth(s.dashboard))
	mux.HandleFunc("GET /lang/{tag}", s.setLang)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)

	mux.HandleFunc("GET /networks/new", s.auth(s.networkNew))
	mux.HandleFunc("POST /networks/new", s.auth(s.networkCreate))
	mux.HandleFunc("GET /networks/{id}", s.auth(s.network))
	mux.HandleFunc("POST /networks/{id}", s.auth(s.networkUpdate))
	mux.HandleFunc("POST /networks/{id}/enabled", s.auth(s.networkEnabled))
	mux.HandleFunc("POST /networks/{id}/delete", s.auth(s.networkDelete))
	mux.HandleFunc("POST /networks/{id}/quote", s.auth(s.networkQuote))
	mux.HandleFunc("POST /networks/{id}/channels", s.auth(s.channelCreate))
	mux.HandleFunc("POST /networks/{id}/channels/update", s.auth(s.channelUpdate))
	mux.HandleFunc("POST /networks/{id}/channels/delete", s.auth(s.channelDelete))
	mux.HandleFunc("POST /networks/{id}/sasl", s.auth(s.sasl))
	mux.HandleFunc("POST /networks/{id}/certfp", s.auth(s.certfp))

	mux.HandleFunc("POST /networks/{id}/reconnect", s.auth(s.networkReconnect))

	mux.HandleFunc("GET /console", s.auth(s.console))
	mux.HandleFunc("POST /console", s.auth(s.consoleRun))

	mux.HandleFunc("GET /watcher", s.auth(s.watcher))
	mux.HandleFunc("POST /watcher/check", s.auth(s.watcherCheck))
	mux.HandleFunc("POST /watcher/policy", s.auth(s.watcherPolicy))

	mux.HandleFunc("GET /users", s.auth(s.users))
	mux.HandleFunc("POST /users/new", s.auth(s.userCreate))
	mux.HandleFunc("POST /users/update", s.auth(s.userUpdate))
	mux.HandleFunc("POST /users/delete", s.auth(s.userDelete))
	mux.HandleFunc("POST /server/notice", s.auth(s.serverNotice))

	mux.Handle("GET /static/", http.FileServerFS(assets))

	var h http.Handler = mux
	if s.prefix != "" {
		h = http.StripPrefix(s.prefix, mux)
	}
	return s.headers(h)
}

// headers sets the defensive headers this app can afford: it embeds nothing and
// loads nothing from anywhere else.
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- plumbing

type handler func(http.ResponseWriter, *http.Request, *Session)

// auth requires a session, and on POST a matching CSRF token.
func (s *Server) auth(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessions.Get(r)
		if sess == nil {
			http.Redirect(w, r, s.prefix+"/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "malformed form", http.StatusBadRequest)
				return
			}
			if r.PostFormValue("csrf") != sess.CSRF {
				http.Error(w, "stale form: reload the page and try again", http.StatusForbidden)
				return
			}
		}
		next(w, r, sess)
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess *Session, name, title, nav string, data any) {
	p := page{Locale: s.locales.Pick(r, s.lang), Title: title, Prefix: s.prefix, Nav: nav, Data: data}
	if sess != nil {
		p.User = sess.User()
		p.IsAdmin = sess.IsAdmin()
		p.CSRF = sess.CSRF
		p.Flash = sess.TakeFlash()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		// The response is likely half-written by now, so this can only be logged.
		fmt.Printf("template %s: %v\n", name, err)
	}
}

// back redirects to where the form was submitted from, with a message.
func (s *Server) back(w http.ResponseWriter, r *http.Request, sess *Session, to string, err error, ok string) {
	if err != nil {
		sess.SetFlash(err.Error(), true)
	} else if ok != "" {
		sess.SetFlash(ok, false)
	}
	http.Redirect(w, r, s.prefix+to, http.StatusSeeOther)
}

// ---------------------------------------------------------------- login

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if s.sessions.Get(r) != nil {
		http.Redirect(w, r, s.prefix+"/", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "login.html", "page.sign_in", "", map[string]any{
		"Addr": s.cfg.Addr, "Error": "", "Username": "",
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")

	sess, err := s.sessions.New(s.cfg, user, pass)
	if err != nil {
		s.render(w, r, nil, "login.html", "page.sign_in", "", map[string]any{
			"Addr":     s.cfg.Addr,
			"Error":    err.Error(),
			"Username": user,
		})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.ID,
		Path:     s.prefix + "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, s.prefix+"/", http.StatusSeeOther)
}

// setLang remembers the reader's choice. It is a preference for display, kept in
// a cookie of its own so it survives signing out and applies to the login page
// too.
func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	if !s.locales.Has(tag) {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     langCookie,
		Value:    tag,
		Path:     s.prefix + "/",
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	// Back where the reader was, as long as it is a page of this program: a
	// redirect target taken from a header is not to be trusted further than that.
	back := s.prefix + "/"
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host && strings.HasPrefix(ref.Path, s.prefix+"/") {
		back = ref.Path
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := s.sessions.Get(r); sess != nil {
		s.sessions.Delete(sess.ID)
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: s.prefix + "/", MaxAge: -1,
	})
	http.Redirect(w, r, s.prefix+"/login", http.StatusSeeOther)
}

// ---------------------------------------------------------------- dashboard

type netRow struct {
	*Network
	Channels int
	Detached int
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sess *Session) {
	var nets []*Network
	var chans []*Channel
	var status []string

	err := sess.Do(s.cfg, func(c *Client) error {
		var err error
		if nets, err = c.ListNetworks(); err != nil {
			return err
		}
		// One call covers the channels of every network: soju prints them with a
		// "/network" suffix when the connection is not bound to one.
		chans, _ = c.Channels("")
		if c.IsAdmin {
			status, _ = c.Serv("server", "status")
		}
		return nil
	})
	if err != nil {
		s.render(w, r, sess, "error.html", "page.error", "networks", err.Error())
		return
	}

	rows := make([]*netRow, 0, len(nets))
	for _, n := range nets {
		row := &netRow{Network: n}
		for _, ch := range chans {
			if ch.Network == n.Name() {
				row.Channels++
				if ch.Detached() {
					row.Detached++
				}
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Name()) < strings.ToLower(rows[j].Name())
	})

	s.render(w, r, sess, "dashboard.html", "page.networks", "networks", map[string]any{
		"Networks": rows,
		"Status":   status,
	})
}

// ---------------------------------------------------------------- networks

// netAttrs reads the network form. Attributes whose value is empty are only sent
// when the field is meant to be clearable: for the password, an empty box means
// "leave it as it is", since the current one is never shown.
func netAttrs(r *http.Request, isNew bool) map[string]string {
	attrs := map[string]string{
		"host":     strings.TrimSpace(r.PostFormValue("host")),
		"port":     strings.TrimSpace(r.PostFormValue("port")),
		"tls":      "1",
		"name":     strings.TrimSpace(r.PostFormValue("name")),
		"nickname": strings.TrimSpace(r.PostFormValue("nickname")),
		"username": strings.TrimSpace(r.PostFormValue("username")),
		"realname": strings.TrimSpace(r.PostFormValue("realname")),
	}
	if r.PostFormValue("tls") == "" {
		attrs["tls"] = "0"
	}
	if p := r.PostFormValue("pass"); p != "" {
		attrs["pass"] = p
	} else if r.PostFormValue("clearpass") != "" {
		attrs["pass"] = ""
	}
	if isNew {
		for k, v := range attrs {
			if v == "" && k != "tls" {
				delete(attrs, k)
			}
		}
	}
	return attrs
}

func (s *Server) networkNew(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.render(w, r, sess, "network_new.html", "page.add_network", "networks", nil)
}

func (s *Server) networkCreate(w http.ResponseWriter, r *http.Request, sess *Session) {
	attrs := netAttrs(r, true)
	if attrs["host"] == "" {
		s.back(w, r, sess, "/networks/new", fmt.Errorf("a host is required"), "")
		return
	}
	var id string
	err := sess.Do(s.cfg, func(c *Client) error {
		var err error
		id, err = c.AddNetwork(attrs)
		return err
	})
	if err != nil {
		s.back(w, r, sess, "/networks/new", err, "")
		return
	}
	s.back(w, r, sess, "/networks/"+id, nil, "Network created; soju is connecting.")
}

type netPage struct {
	Net      *Network
	Channels []*Channel
	SASL     []string
	CertFP   []string
	Status   string // the `network status` line for this network, as soju wrote it
	Enabled  bool
	Nameless bool
}

func (s *Server) network(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	d := &netPage{}
	err := sess.Do(s.cfg, func(c *Client) error {
		var err error
		if d.Net, err = c.Network(id); err != nil {
			return err
		}
		name := d.Net.Name()
		d.Channels, _ = c.Channels(name)
		d.SASL, _ = c.Serv("sasl", "status", "-network", name)
		d.CertFP, _ = c.Serv("certfp", "fingerprint", "-network", name)

		// Whether a network is enabled is not one of the attributes the
		// bouncer-networks extension carries, so it is read off the line
		// `network status` prints for it.
		if lines, err := c.Serv("network", "status"); err == nil {
			for _, l := range lines {
				if strings.HasPrefix(l, name+" [") || strings.HasPrefix(l, name+" (") {
					d.Status = l
				}
			}
		}
		return nil
	})
	if err != nil {
		s.render(w, r, sess, "error.html", "page.error", "networks", err.Error())
		return
	}
	d.Enabled = !strings.Contains(d.Status, "disabled")
	d.Nameless = d.Net.Attr("name") == ""
	s.render(w, r, sess, "network.html", d.Net.Name(), "networks", d)
}

func (s *Server) networkUpdate(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	err := sess.Do(s.cfg, func(c *Client) error {
		return c.ChangeNetwork(id, netAttrs(r, false))
	})
	s.back(w, r, sess, "/networks/"+id, err, "Network saved.")
}

// networkEnabled goes through BouncerServ: soju.im/bouncer-networks has no
// attribute for it.
func (s *Server) networkEnabled(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	on := r.PostFormValue("enabled") == "1"
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		_, err = c.Serv("network", "update", n.Name(), "-enabled", fmt.Sprint(on))
		return err
	})
	msg := "Network disabled."
	if on {
		msg = "Network enabled."
	}
	s.back(w, r, sess, "/networks/"+id, err, msg)
}

func (s *Server) networkDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	err := sess.Do(s.cfg, func(c *Client) error {
		return c.DeleteNetwork(id)
	})
	if err != nil {
		s.back(w, r, sess, "/networks/"+id, err, "")
		return
	}
	s.back(w, r, sess, "/", nil, "Network deleted, along with its stored history.")
}

func (s *Server) networkQuote(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	line := strings.TrimSpace(r.PostFormValue("line"))
	if line == "" {
		s.back(w, r, sess, "/networks/"+id, fmt.Errorf("nothing to send"), "")
		return
	}
	var out []string
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		out, err = c.Serv("network", "quote", n.Name(), line)
		return err
	})
	s.back(w, r, sess, "/networks/"+id, err, strings.Join(out, " "))
}

// ---------------------------------------------------------------- channels

// chanFlags reads the per-channel options shared by create and update.
func chanFlags(r *http.Request) []string {
	var out []string
	for _, f := range []string{"relay-detached", "reattach-on", "detach-on"} {
		if v := r.PostFormValue(f); v != "" {
			out = append(out, "-"+f, v)
		}
	}
	if v := strings.TrimSpace(r.PostFormValue("detach-after")); v != "" {
		out = append(out, "-detach-after", v)
	}
	return out
}

// chanArg builds the "#channel/network" form BouncerServ needs when the
// connection is not bound to a network.
func chanArg(channel, network string) string {
	return channel + "/" + network
}

func (s *Server) channelCreate(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.PostFormValue("channel"))
	if name == "" {
		s.back(w, r, sess, "/networks/"+id, fmt.Errorf("no channel name given"), "")
		return
	}
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		args := []string{"channel", "create", chanArg(name, n.Name())}
		if r.PostFormValue("detached") == "true" {
			args = append(args, "-detached", "true")
		}
		args = append(args, chanFlags(r)...)
		_, err = c.Serv(args...)
		return err
	})
	s.back(w, r, sess, "/networks/"+id, err, "Joined "+name+".")
}

func (s *Server) channelUpdate(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	name := r.PostFormValue("channel")
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		args := []string{"channel", "update", chanArg(name, n.Name())}
		if v := r.PostFormValue("detached"); v != "" {
			args = append(args, "-detached", v)
		}
		args = append(args, chanFlags(r)...)
		_, err = c.Serv(args...)
		return err
	})
	s.back(w, r, sess, "/networks/"+id, err, "Channel "+name+" updated.")
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	name := r.PostFormValue("channel")
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		_, err = c.Serv("channel", "delete", chanArg(name, n.Name()))
		return err
	})
	s.back(w, r, sess, "/networks/"+id, err, "Left "+name+" and forgot it.")
}

// ---------------------------------------------------------------- sasl, certfp

func (s *Server) sasl(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	action := r.PostFormValue("action")
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		switch action {
		case "reset":
			_, err = c.Serv("sasl", "reset", "-network", n.Name())
		default:
			user := strings.TrimSpace(r.PostFormValue("sasl_username"))
			pass := r.PostFormValue("sasl_password")
			if user == "" || pass == "" {
				return fmt.Errorf("both an account name and a password are needed")
			}
			_, err = c.Serv("sasl", "set-plain", "-network", n.Name(), user, pass)
		}
		return err
	})
	msg := "SASL credentials stored; reconnect the network to use them."
	if action == "reset" {
		msg = "SASL disabled and credentials removed."
	}
	s.back(w, r, sess, "/networks/"+id, err, msg)
}

func (s *Server) certfp(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	keyType := r.PostFormValue("key-type")
	if keyType == "" {
		keyType = "ed25519"
	}
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		_, err = c.Serv("certfp", "generate", "-network", n.Name(), "-key-type", keyType)
		return err
	})
	s.back(w, r, sess, "/networks/"+id, err,
		"Certificate generated. Register the fingerprint with the network's services, then reconnect.")
}

// ---------------------------------------------------------------- console

func (s *Server) console(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.render(w, r, sess, "console.html", "page.console", "console", map[string]any{
		"Command": "", "Error": "", "Output": nil,
	})
}

func (s *Server) consoleRun(w http.ResponseWriter, r *http.Request, sess *Session) {
	cmd := strings.TrimSpace(r.PostFormValue("command"))
	data := map[string]any{"Command": cmd, "Error": "", "Output": nil}
	if cmd != "" {
		var out []string
		err := sess.Do(s.cfg, func(c *Client) error {
			var err error
			// The line is split the way BouncerServ itself splits it, quotes
			// included, then handed over word by word.
			words, err2 := splitWords(cmd)
			if err2 != nil {
				return err2
			}
			out, err = c.Serv(words...)
			return err
		})
		if err != nil {
			data["Error"] = err.Error()
		}
		data["Output"] = out
	}
	s.render(w, r, sess, "console.html", "page.console", "console", data)
}

// ---------------------------------------------------------------- watcher

type watcherPage struct {
	StateDir string
	States   []NetworkState
	Log      []string
	Err      string
	Policy   string // the policy file as text, when there is one
	Editable bool
	OwnOnly  bool // not an admin: only the manual check is available
	Probes   []ProbeResult
}

// watcherData reads what the watcher left behind. The state, the log and the
// policy describe one user's networks — whoever the watcher was configured for —
// so they are shown to admins only; the manual check is everyone's, since it runs
// on the caller's own connection.
func (s *Server) watcherData(sess *Session) *watcherPage {
	d := &watcherPage{StateDir: s.stateDir, Editable: s.policyPath != ""}
	if !sess.IsAdmin() {
		d.Editable = false
		d.OwnOnly = true
		return d
	}
	if s.stateDir == "" {
		d.Err = "This program was started without -watch-state-dir, so it cannot see the watcher."
		return d
	}
	var err error
	if d.States, err = ReadStates(s.stateDir); err != nil {
		d.Err = "cannot read the watcher's state: " + err.Error()
	}
	if lines, err := ReadLog(s.stateDir, 200); err == nil {
		d.Log = lines
	} else if d.Err == "" {
		d.Err = "no log yet: the watcher may never have run."
	}
	if s.policyPath != "" {
		if b, err := os.ReadFile(s.policyPath); err == nil {
			d.Policy = string(b)
		} else {
			d.Err = "cannot read the policy file: " + err.Error()
			d.Editable = false
		}
	}
	return d
}

func (s *Server) watcher(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.render(w, r, sess, "watcher.html", "page.watcher", "watcher", s.watcherData(sess))
}

// watcherCheck runs the zombie check now, as the signed-in user, so it needs no
// stored credentials of its own.
func (s *Server) watcherCheck(w http.ResponseWriter, r *http.Request, sess *Session) {
	var nets []*Network
	err := sess.Do(s.cfg, func(c *Client) error {
		var err error
		nets, err = c.ListNetworks()
		return err
	})
	d := s.watcherData(sess)
	if err != nil {
		d.Err = err.Error()
	} else {
		user, pass := sess.Credentials()
		d.Probes = ProbeNetworks(s.cfg, user, pass, "watch", nets)
	}
	s.render(w, r, sess, "watcher.html", "page.watcher", "watcher", d)
}

func (s *Server) watcherPolicy(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	if s.policyPath == "" {
		http.Error(w, "no policy file configured", http.StatusForbidden)
		return
	}
	text := strings.ReplaceAll(r.PostFormValue("policy"), "\r\n", "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n" // a browser drops the last newline; a config file should keep it
	}

	// Refuse to save something the watcher would then choke on, and say which keys
	// a policy is not allowed to carry.
	tmp, err := os.CreateTemp(filepath.Dir(s.policyPath), ".policy-*")
	if err != nil {
		s.back(w, r, sess, "/watcher", err, "")
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		s.back(w, r, sess, "/watcher", err, "")
		return
	}
	tmp.Close()

	parsed, err := LoadPolicy(tmp.Name())
	if err != nil {
		s.back(w, r, sess, "/watcher", err, "")
		return
	}
	empty := &Config{}
	if refused := empty.MergePolicy(parsed); len(refused) > 0 {
		s.back(w, r, sess, "/watcher",
			fmt.Errorf("a policy file cannot set: %s — those belong in the watcher's own configuration",
				strings.Join(refused, ", ")), "")
		return
	}

	if err := os.WriteFile(s.policyPath, []byte(text), 0o644); err != nil {
		s.back(w, r, sess, "/watcher", err, "")
		return
	}
	s.back(w, r, sess, "/watcher", nil, "Policy saved; the watcher picks it up on its next pass.")
}

// networkReconnect is what the watcher does when it finds a zombie: rewriting the
// address is what makes soju drop the socket and dial again.
func (s *Server) networkReconnect(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	back := "/networks/" + id
	if r.PostFormValue("from") == "watcher" {
		back = "/watcher"
	}
	var name string
	err := sess.Do(s.cfg, func(c *Client) error {
		n, err := c.Network(id)
		if err != nil {
			return err
		}
		name = n.Name()
		_, err = c.Serv("network", "update", name, "-addr", n.Addr())
		return err
	})
	s.back(w, r, sess, back, err, "Reconnecting "+name+".")
}

// ---------------------------------------------------------------- users, admin

func (s *Server) users(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var users []*User
	var status []string
	err := sess.Do(s.cfg, func(c *Client) error {
		var err error
		if users, err = c.Users(); err != nil {
			return err
		}
		status, _ = c.Serv("server", "status")
		return nil
	})
	if err != nil {
		s.render(w, r, sess, "error.html", "page.error", "users", err.Error())
		return
	}
	s.render(w, r, sess, "users.html", "page.users", "users", map[string]any{
		"Users":  users,
		"Status": status,
	})
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	args := []string{"user", "create",
		"-username", strings.TrimSpace(r.PostFormValue("username")),
		"-password", r.PostFormValue("password"),
	}
	if r.PostFormValue("admin") != "" {
		// In `user create` this is a plain boolean flag, which Go's flag package
		// only accepts glued to its value. Elsewhere soju uses a custom flag type
		// that takes the value as a separate word.
		args = append(args, "-admin=true")
	}
	if v := strings.TrimSpace(r.PostFormValue("nick")); v != "" {
		args = append(args, "-nick", v)
	}
	if v := strings.TrimSpace(r.PostFormValue("realname")); v != "" {
		args = append(args, "-realname", v)
	}
	if v := strings.TrimSpace(r.PostFormValue("max-networks")); v != "" {
		args = append(args, "-max-networks", v)
	}
	err := sess.Do(s.cfg, func(c *Client) error {
		_, err := c.Serv(args...)
		return err
	})
	s.back(w, r, sess, "/users", err, "User created.")
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("username"))
	args := []string{"user", "update", name}
	if v := r.PostFormValue("password"); v != "" {
		args = append(args, "-password", v)
	}
	for _, f := range []string{"admin", "enabled"} {
		if v := r.PostFormValue(f); v != "" {
			args = append(args, "-"+f, v)
		}
	}
	if v := strings.TrimSpace(r.PostFormValue("max-networks")); v != "" {
		args = append(args, "-max-networks", v)
	}
	if len(args) == 3 {
		s.back(w, r, sess, "/users", fmt.Errorf("nothing to change for %s", name), "")
		return
	}
	err := sess.Do(s.cfg, func(c *Client) error {
		_, err := c.Serv(args...)
		return err
	})
	s.back(w, r, sess, "/users", err, "User "+name+" updated.")
}

// userDelete mirrors soju's own two-step deletion: asking without a token makes
// soju reply with the token, which the confirmation page then sends back.
func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("username"))
	token := strings.TrimSpace(r.PostFormValue("token"))

	if token == "" {
		var reply []string
		err := sess.Do(s.cfg, func(c *Client) error {
			var err error
			reply, err = c.Serv("user", "delete", name)
			return err
		})
		if err != nil {
			s.back(w, r, sess, "/users", err, "")
			return
		}
		// The reply reads: To confirm user deletion, send "user delete <name> <token>"
		tok := ""
		if len(reply) > 0 {
			f := strings.Fields(strings.Trim(reply[0], `"`))
			tok = strings.Trim(f[len(f)-1], `"`)
		}
		s.render(w, r, sess, "confirm_user.html", "page.delete_user", "users", map[string]any{
			"Username": name,
			"Token":    tok,
			"Reply":    reply,
		})
		return
	}

	err := sess.Do(s.cfg, func(c *Client) error {
		_, err := c.Serv("user", "delete", name, token)
		return err
	})
	s.back(w, r, sess, "/users", err, "User "+name+" deleted.")
}

func (s *Server) serverNotice(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	text := strings.TrimSpace(r.PostFormValue("notice"))
	if text == "" {
		s.back(w, r, sess, "/users", fmt.Errorf("nothing to broadcast"), "")
		return
	}
	err := sess.Do(s.cfg, func(c *Client) error {
		_, err := c.Serv("server", "notice", text)
		return err
	})
	s.back(w, r, sess, "/users", err, "Notice broadcast to every connected user.")
}
