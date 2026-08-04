package main

// The watcher: two jobs soju does not do for itself, run on a timer.
//
//   - Zombie connections. soju can hold a network as "connected" while the socket
//     on the other side is dead: the state says connected, channels are listed,
//     and nothing sent to the network arrives anywhere. The check is a WHOIS sent
//     *through* soju on a connection bound to that network. A live upstream
//     answers 311 or 401; a dead one answers nothing, so the timeout is the
//     diagnosis. Two failures in a row force a reconnect, because one lagged
//     server should not be enough.
//
//   - Keeping the nick. soju's connect commands only run when a connection
//     registers, so after a netsplit — where nothing reconnects — a nick lost to a
//     ghost stays lost. Same escalation as a human would do: NICK, then the
//     network's services, then identify first; then stop for a while, since by
//     then the nick may simply belong to somebody else.
//
// Everything here goes through soju: raw lines via `network quote`, no writes to
// its database and no second connection to the remote network.

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

// probeTimeout is how long a live network gets to answer a WHOIS relayed by soju.
// Silence past this is what "zombie" means here, so it has to be generous enough
// for a lagged server.
const probeTimeout = 20 * time.Second

type watchState struct {
	NickStep   int   `json:"nick_step"`
	NickLast   int64 `json:"nick_last"`
	ProbeFails int   `json:"probe_fails"`
	LastRepair int64 `json:"last_repair"`
}

// passStats is what one pass reports at the end. A healthy pass has nothing else
// to say, and silence in the journal would not prove it ran.
type passStats struct {
	checked, skipped, silent, repaired, nick int
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

// Run does one pass and returns. Repeating is left to a timer — systemd's, or the
// loop in RunForever.
func (w *Watcher) Run() error {
	// The unbound connection is the one that can talk to BouncerServ about every
	// network at once.
	admin, err := Dial(w.cfg, w.user, w.password)
	if err != nil {
		return err
	}
	defer admin.Close()

	if w.nick == "" {
		// Unbound, soju welcomes us with the user's own nick, which is the one the
		// networks are supposed to show.
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
	log.Printf("%d networks checked, %d skipped: %d silent, %d reconnected, %d nick attempts",
		s.checked, s.skipped, s.silent, s.repaired, s.nick)
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

	// A connection bound to this network. draft/chathistory matters: without it
	// soju replays the stored backlog to every client that binds, which for a
	// watchdog would mean dragging history across the socket on every pass.
	bound, err := dial(w.cfg, w.user, w.password, dialOpts{
		network: name,
		client:  w.client,
		caps:    []string{"draft/chathistory", "soju.im/no-implicit-names"},
	})
	if err != nil {
		// Failing to bind says nothing about the upstream: soju itself answered.
		return fmt.Errorf("cannot bind: %v", err)
	}
	defer bound.Close()

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

	// The upstream is alive, so the nick soju registered with is trustworthy.
	current := bound.Nick
	if current == w.nick {
		if st.NickStep > 0 {
			log.Printf("%s: nick is %s again", name, w.nick)
			st.NickStep, st.NickLast = 0, 0
		}
		w.saveState(name, st)
		return nil
	}

	held := "nobody holds it"
	if inUse {
		held = "somebody holds it"
	}
	log.Printf("%s: nick is %q, not %s (%s)", name, current, w.nick, held)
	w.recoverNick(bound, name, current, ns, st)
	w.saveState(name, st)
	return nil
}

// probe asks soju to WHOIS a nick on the bound network. answered is false when
// nothing came back at all, which is the signature of a dead upstream socket;
// inUse says whether the nick is taken.
func (w *Watcher) probe(bound *Client, nick string) (answered, inUse bool) {
	// 311 the nick exists, 401 it does not, 318 ends the reply either way.
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
		return // a rehearsal must not leave the escalation half-way through
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.WriteFile(w.statePath(network), b, 0o600); err != nil {
		log.Printf("cannot write state for %s: %v", network, err)
	}
}

// repair forces soju to drop the dead socket and dial again. Rewriting the
// address is what makes it reconnect; the value is the one soju already has.
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

// recoverNick escalates the way a person would, one step per pass.
func (w *Watcher) recoverNick(bound *Client, name, current string, ns *Section, st *watchState) {
	now := time.Now()
	if st.NickStep >= w.maxSteps {
		if now.Sub(time.Unix(st.NickLast, 0)) < w.cooldown {
			return // stopped for now: the nick may belong to somebody else
		}
		st.NickStep = 0 // the wait is over, start again
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
		// Nothing to wait for: what services answer is a notice, and the next pass
		// is what checks whether it worked.
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

// ---------------------------------------------------------------- manual check

// ProbeResult is what one network answered to a check asked for by hand.
type ProbeResult struct {
	Network  string
	ID       string
	State    string
	Answered bool
	Nick     string
	Note     string
}

// ProbeNetworks runs the zombie check once, for the web interface, using the
// credentials of whoever is signed in. It reports and changes nothing: repairing
// stays a button of its own.
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
		// WHOIS of the nick soju itself registered with: alive, it must come back.
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

// redact keeps a password out of the log.
func redact(line, pass string) string {
	if pass == "" {
		return line
	}
	return strings.ReplaceAll(line, pass, "****")
}

// alert hands the message to the configured command on stdin — `msmtp you@example
// .org`, `mail -s …`, anything. Without one, the log is the only channel.
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

// logFile is the watcher's own log, kept beside its state so a web interface with
// no access to the journal can still show it. It is trimmed to keep the tail,
// since nothing rotates it.
const (
	logName     = "watch.log"
	logMaxBytes = 128 << 10
)

// OpenLog sends the log to stderr — the journal, under systemd — and to a file in
// the state directory.
func (w *Watcher) OpenLog() {
	path := filepath.Join(w.stateDir, logName)
	if st, err := os.Stat(path); err == nil && st.Size() > logMaxBytes {
		if b, err := os.ReadFile(path); err == nil {
			keep := b[len(b)-logMaxBytes/2:]
			if i := bytes.IndexByte(keep, '\n'); i >= 0 {
				keep = keep[i+1:] // start on a whole line
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

// ReadLog returns the tail of the watcher's log, newest lines last.
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

// NetworkState is one network's watcher state, for display.
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

// ReadStates loads whatever state the watcher has left behind.
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
