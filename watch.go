package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const probeTimeout = 20 * time.Second

type watchState struct {
	NickStep   int              `json:"nick_step"`
	NickLast   int64            `json:"nick_last"`
	ProbeFails int              `json:"probe_fails"`
	LastRepair int64            `json:"last_repair"`
	OpLast     map[string]int64 `json:"op_last,omitempty"`
}

type passStats struct {
	checked, skipped, silent, repaired, nick, opped int
}

type Watcher struct {
	stats passStats

	cfg      ServerConfig
	conf     *Config
	user     string
	password string
	nick     string
	client   string
	interval time.Duration
	cooldown time.Duration
	maxSteps int
	stateDir string
	alertCmd string
	dry      bool
}

func NewWatcher(cfg ServerConfig, conf *Config, stateDir string, dry bool) (*Watcher, error) {
	s := conf.Section("watch")
	w := &Watcher{
		cfg:      cfg,
		conf:     conf,
		user:     s.Get("user"),
		password: s.Get("password"),
		nick:     s.Get("nick"),
		client:   s.Get("client"),
		stateDir: stateDir,
		alertCmd: s.Get("alert-command"),
		dry:      dry,
	}
	if w.user == "" || w.password == "" {
		return nil, fmt.Errorf("the [watch] section needs both user and password")
	}
	if w.client == "" {
		w.client = "watch"
	}
	var err error
	if w.interval, err = s.Duration("interval", 20*time.Minute); err != nil {
		return nil, err
	}
	if w.cooldown, err = s.Duration("nick-cooldown", time.Hour); err != nil {
		return nil, err
	}
	w.maxSteps = 3
	if err := os.MkdirAll(w.stateDir, 0o700); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Watcher) Run() error {

	admin, err := Dial(w.cfg, w.user, w.password)
	if err != nil {
		return err
	}
	defer admin.Close()

	if w.nick == "" {

		w.nick = admin.Nick
	}
	if w.nick == "" {
		return fmt.Errorf("no nick to watch for: set nick in the [watch] section")
	}

	nets, err := admin.ListNetworks()
	if err != nil {
		return err
	}

	w.stats = passStats{}
	for _, n := range nets {
		name := n.Name()
		if n.State() != "connected" {
			log.Printf("%s: %s, skipped", name, n.State())
			w.stats.skipped++
			continue
		}
		ns := w.conf.NetworkSection(name)
		if ns.Bool("skip") {
			w.stats.skipped++
			continue
		}
		w.stats.checked++
		if err := w.checkNetwork(admin, n, ns); err != nil {
			log.Printf("%s: %v", name, err)
		}
	}

	s := w.stats
	log.Printf("%d networks checked, %d skipped: %d silent, %d reconnected, %d nick attempts, %d op requests",
		s.checked, s.skipped, s.silent, s.repaired, s.nick, s.opped)
	return nil
}

func (w *Watcher) RunForever() {
	for {
		if err := w.Run(); err != nil {
			log.Printf("pass failed: %v", err)
		}
		time.Sleep(w.interval)
	}
}

func (w *Watcher) checkNetwork(admin *Client, n *Network, ns *Section) error {
	name := n.Name()
	st := w.loadState(name)

	bound, err := dial(w.cfg, w.user, w.password, dialOpts{
		network: name,
		client:  w.client,
		caps:    []string{"draft/chathistory", "soju.im/no-implicit-names"},
	})
	if err != nil {

		return fmt.Errorf("cannot bind: %v", err)
	}
	defer bound.Close()

	bound.Send("AWAY :watch")

	answered, inUse := w.probe(bound, w.nick)
	if !answered {
		w.stats.silent++
		st.ProbeFails++
		log.Printf("%s: no answer to WHOIS through soju (%d in a row)", name, st.ProbeFails)
		if st.ProbeFails >= 2 {
			w.repair(admin, n, st)
		}
		w.saveState(name, st)
		return nil
	}
	if st.ProbeFails > 0 {
		log.Printf("%s: answering again", name)
	}
	st.ProbeFails = 0

	current := bound.Nick
	if current == w.nick {
		if st.NickStep > 0 {
			log.Printf("%s: nick is %s again", name, w.nick)
			st.NickStep, st.NickLast = 0, 0
		}

		w.keepOps(bound, name, current, ns, st)
		w.saveState(name, st)
		return nil
	}

	held := "nobody holds it"
	if inUse {
		held = "somebody holds it"
	}
	log.Printf("%s: nick is %q, not %s (%s)", name, current, w.nick, held)

	if ns.Get("recover") == "reconnect" {
		w.reconnectForNick(admin, n, current, st)
	} else {
		w.recoverNick(bound, name, current, ns, st)
	}
	w.saveState(name, st)
	return nil
}

func (w *Watcher) probe(bound *Client, nick string) (answered, inUse bool) {

	msgs, ok, err := bound.Await(formatMessage("WHOIS", nick),
		[]string{"311", "401", "318"}, probeTimeout)
	if err != nil || !ok {
		return false, false
	}
	for _, m := range msgs {
		if m.Command == "311" {
			return true, true
		}
	}
	return true, false
}

func (w *Watcher) loadState(network string) *watchState {
	st := &watchState{}
	b, err := os.ReadFile(w.statePath(network))
	if err == nil {
		json.Unmarshal(b, st)
	}
	return st
}

func (w *Watcher) saveState(network string, st *watchState) {
	if w.dry {
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.WriteFile(w.statePath(network), b, 0o600); err != nil {
		log.Printf("cannot write state for %s: %v", network, err)
	}
}

func (w *Watcher) repair(admin *Client, n *Network, st *watchState) {
	name, addr := n.Name(), n.Addr()
	if w.dry {
		log.Printf("%s: would run: network update %s -addr %s", name, name, addr)
		return
	}
	out, err := admin.Serv("network", "update", name, "-addr", addr)
	st.LastRepair = time.Now().Unix()
	st.ProbeFails = 0
	if err != nil {
		log.Printf("%s: reconnect failed: %v", name, err)
		w.alert("soju: zombie connection on "+name+", and the repair failed",
			fmt.Sprintf("The network %q was held as connected by soju while the nick %q was\n"+
				"unreachable through it: the upstream socket is dead.\n\n"+
				"Forcing a reconnect failed: %v\n\nSort it out by hand.\n", name, w.nick, err))
		return
	}
	w.stats.repaired++
	log.Printf("%s: zombie connection, reconnect forced", name)
	w.alert("soju: zombie connection on "+name,
		fmt.Sprintf("The network %q was held as connected by soju, but a WHOIS for %q sent\n"+
			"through it went unanswered twice in a row: the upstream socket was dead.\n\n"+
			"Address: %s\n\nThe watcher forced a reconnect with:\n  network update %s -addr %s\n\n"+
			"soju answered: %s\n", name, w.nick, addr, name, addr, strings.Join(out, " ")))
}

func (w *Watcher) recoverNick(bound *Client, name, current string, ns *Section, st *watchState) {
	now := time.Now()
	if st.NickStep >= w.maxSteps {
		if now.Sub(time.Unix(st.NickLast, 0)) < w.cooldown {
			return
		}
		st.NickStep = 0
	}
	st.NickStep++
	st.NickLast = now.Unix()
	w.stats.nick++

	pass := ns.Get("password")
	expand := func(k string) string {
		v := ns.Get(k)
		if v == "" {
			return ""
		}
		return strings.NewReplacer("{nick}", w.nick, "{pass}", pass).Replace(v)
	}
	quote := func(line string) {
		if line == "" {
			return
		}
		if w.dry {
			log.Printf("%s: would send: %s", name, redact(line, pass))
			return
		}

		if err := bound.Send(line); err != nil {
			log.Printf("%s: cannot send %q: %v", name, redact(line, pass), err)
		}
	}

	switch st.NickStep {
	case 1:
		log.Printf("%s: attempt 1, plain NICK", name)
		quote(formatMessage("NICK", w.nick))
	case 2:
		log.Printf("%s: attempt 2, asking the network's services", name)
		quote(expand("recover"))
		time.Sleep(3 * time.Second)
		quote(formatMessage("NICK", w.nick))
	case 3:
		log.Printf("%s: attempt 3, identify then recover", name)
		quote(expand("identify"))
		time.Sleep(2 * time.Second)
		quote(expand("recover"))
		time.Sleep(3 * time.Second)
		quote(formatMessage("NICK", w.nick))
		log.Printf("%s: three attempts failed, waiting %s before trying again", name, w.cooldown)
		w.alert("soju: cannot get the nick back on "+name,
			fmt.Sprintf("On %q the nick is %q instead of %q, and three attempts did not get it\n"+
				"back. Waiting %s before trying again — it may simply belong to somebody else\n"+
				"now.\n", name, current, w.nick, w.cooldown))
	}
}

func (w *Watcher) reconnectForNick(admin *Client, n *Network, current string, st *watchState) {
	now := time.Now()
	name := n.Name()
	if st.NickStep > 0 && now.Sub(time.Unix(st.NickLast, 0)) < w.cooldown {
		return
	}
	st.NickStep = 1
	st.NickLast = now.Unix()
	w.stats.nick++
	addr := n.Addr()
	if w.dry {
		log.Printf("%s: would run: network update %s -addr %s (reclaim %s by reconnect)", name, name, addr, w.nick)
		return
	}
	log.Printf("%s: nick is %q, forcing a reconnect to reclaim %s via SASL", name, current, w.nick)
	out, err := admin.Serv("network", "update", name, "-addr", addr)
	st.LastRepair = now.Unix()
	if err != nil {
		log.Printf("%s: reconnect failed: %v", name, err)
		w.alert("soju: cannot reclaim the nick on "+name,
			fmt.Sprintf("On %q the nick is %q instead of %q. The watcher tried to reclaim it by\n"+
				"forcing a reconnect (SASL-only network), but that failed: %v\n\n"+
				"Sort it out by hand.\n", name, current, w.nick, err))
		return
	}
	w.stats.repaired++
	log.Printf("%s: reconnect forced to reclaim the nick (soju: %s)", name, strings.Join(out, " "))
}

func (w *Watcher) keepOps(bound *Client, name, current string, ns *Section, st *watchState) {
	chans := splitList(ns.Get("op-channels"))
	if len(chans) == 0 {
		return
	}
	tmpl := ns.Get("op-command")
	if tmpl == "" {
		tmpl = "PRIVMSG ChanServ :OP {chan}"
	}
	now := time.Now()
	for _, ch := range chans {
		opped, known := w.isOpped(bound, ch, current)
		if !known {
			continue
		}
		if opped {
			delete(st.OpLast, ch)
			continue
		}
		if last, ok := st.OpLast[ch]; ok && now.Sub(time.Unix(last, 0)) < w.cooldown {
			continue
		}
		line := strings.NewReplacer("{chan}", ch, "{nick}", current).Replace(tmpl)
		if w.dry {
			log.Printf("%s: would send: %s", name, line)
		} else {
			log.Printf("%s: not opped in %s, asking services", name, ch)
			if err := bound.Send(line); err != nil {
				log.Printf("%s: cannot ask op for %s: %v", name, ch, err)
				continue
			}
		}
		if st.OpLast == nil {
			st.OpLast = map[string]int64{}
		}
		st.OpLast[ch] = now.Unix()
		w.stats.opped++
	}
}

func (w *Watcher) isOpped(bound *Client, channel, nick string) (opped, known bool) {
	msgs, ok, err := bound.Await(formatMessage("NAMES", channel),
		[]string{"366", "403", "442", "401"}, probeTimeout)
	if err != nil || !ok {
		return false, false
	}
	for _, m := range msgs {
		if m.Command != "353" || !strings.EqualFold(m.Param(2), channel) {
			continue
		}
		for _, tok := range strings.Fields(m.Param(len(m.Params) - 1)) {
			i := 0
			for i < len(tok) && strings.IndexByte("~&@%+", tok[i]) >= 0 {
				i++
			}
			if !strings.EqualFold(tok[i:], nick) {
				continue
			}
			return strings.ContainsAny(tok[:i], "~&@"), true
		}
	}
	return false, false
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

type ProbeResult struct {
	Network  string
	ID       string
	State    string
	Answered bool
	Nick     string
	Note     string
}

func ProbeNetworks(cfg ServerConfig, user, password, client string, nets []*Network) []ProbeResult {
	if client == "" {
		client = "watch"
	}
	out := make([]ProbeResult, 0, len(nets))
	for _, n := range nets {
		r := ProbeResult{Network: n.Name(), ID: n.ID, State: n.State()}
		if n.State() != "connected" {
			r.Note = "not connected"
			out = append(out, r)
			continue
		}
		bound, err := dial(cfg, user, password, dialOpts{
			network: n.Name(),
			client:  client,
			caps:    []string{"draft/chathistory", "soju.im/no-implicit-names"},
		})
		if err != nil {
			r.Note = "cannot bind: " + err.Error()
			out = append(out, r)
			continue
		}
		r.Nick = bound.Nick

		_, ok, err := bound.Await(formatMessage("WHOIS", bound.Nick),
			[]string{"311", "401", "318"}, probeTimeout)
		bound.Close()
		r.Answered = ok && err == nil
		if !r.Answered {
			r.Note = "no answer: the upstream socket looks dead"
		}
		out = append(out, r)
	}
	return out
}

func redact(line, pass string) string {
	if pass == "" {
		return line
	}
	return strings.ReplaceAll(line, pass, "****")
}

func (w *Watcher) alert(subject, body string) {
	log.Printf("alert: %s", subject)
	if w.alertCmd == "" {
		return
	}
	msg := fmt.Sprintf("Subject: %s\nContent-Type: text/plain; charset=UTF-8\n\n%s", subject, body)
	cmd := exec.Command("sh", "-c", w.alertCmd)
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("alert command failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

const (
	logName     = "watch.log"
	logMaxBytes = 128 << 10
)

func (w *Watcher) OpenLog() {
	path := filepath.Join(w.stateDir, logName)
	if st, err := os.Stat(path); err == nil && st.Size() > logMaxBytes {
		if b, err := os.ReadFile(path); err == nil {
			keep := b[len(b)-logMaxBytes/2:]
			if i := bytes.IndexByte(keep, '\n'); i >= 0 {
				keep = keep[i+1:]
			}
			os.WriteFile(path, keep, 0o600)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("cannot write %s: %v", path, err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
}

func ReadLog(stateDir string, maxLines int) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, logName))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

type NetworkState struct {
	Network string
	watchState
}

func (s NetworkState) LastRepairTime() string {
	if s.LastRepair == 0 {
		return ""
	}
	return time.Unix(s.LastRepair, 0).Format("2006-01-02 15:04")
}

func ReadStates(stateDir string) ([]NetworkState, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return nil, err
	}
	var out []NetworkState
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			continue
		}
		ns := NetworkState{Network: strings.TrimSuffix(name, ".json")}
		if json.Unmarshal(b, &ns.watchState) == nil {
			out = append(out, ns)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Network) < strings.ToLower(out[j].Network)
	})
	return out, nil
}

func (w *Watcher) statePath(network string) string {
	safe := strings.Map(func(r rune) rune {
		if strings.ContainsRune("/\\:*?\"<>| ", r) {
			return '_'
		}
		return r
	}, network)
	return filepath.Join(w.stateDir, safe+".json")
}
