package main

// One IRC connection to soju per logged-in web session, plus the soju-specific
// operations built on top of it.
//
// Two different interfaces are used, deliberately:
//
//   - networks go through the soju.im/bouncer-networks extension, which is a
//     structured protocol (attribute lists, numeric ids, error replies);
//   - everything else goes through BouncerServ, whose replies are lines of prose
//     meant for humans. Those are shown as they arrive wherever possible, and
//     parsed only where the UI needs the fields.
//
// soju does not implement labeled-response, so replies cannot be tagged and
// matched. Instead a request holds a lock, sends its command, and then sends a
// PING carrying a nonce: IRC is ordered per connection, so every line belonging
// to the command has arrived by the time the matching PONG comes back.

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	requestTimeout = 20 * time.Second
	dialTimeout    = 15 * time.Second
	handshakeLimit = 30 * time.Second
)

var errClosed = errors.New("connection to soju closed")

// ServerConfig describes how to reach soju. It is set once, from the flags.
type ServerConfig struct {
	Addr     string // host:port
	TLS      bool
	Insecure bool // accept any certificate (self-signed soju setups)
}

type Client struct {
	cfg ServerConfig

	conn net.Conn
	in   chan *Message

	wmu sync.Mutex // serializes writes
	rmu sync.Mutex // serializes requests, so replies cannot interleave

	Username string
	IsAdmin  bool
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice; a panic here is better than a
		// silently predictable token.
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Dial connects to soju and authenticates with SASL PLAIN. Success means the
// credentials are soju's own, which is what this program uses as its login: no
// separate user store, no password of its own.
func Dial(cfg ServerConfig, username, password string) (*Client, error) {
	var conn net.Conn
	var err error
	d := &net.Dialer{Timeout: dialTimeout}
	if cfg.TLS {
		host, _, _ := net.SplitHostPort(cfg.Addr)
		conn, err = tls.DialWithDialer(d, "tcp", cfg.Addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.Insecure,
		})
	} else {
		conn, err = d.Dial("tcp", cfg.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot reach soju at %s: %w", cfg.Addr, err)
	}

	c := &Client{cfg: cfg, conn: conn, in: make(chan *Message, 256), Username: username}
	if err := c.handshake(username, password); err != nil {
		conn.Close()
		return nil, err
	}
	go c.readLoop()

	// Admin commands are hidden from ordinary users, so asking is the only way to
	// know which UI to show.
	if _, err := c.Serv("user", "status"); err == nil {
		c.IsAdmin = true
	}
	return c, nil
}

func (c *Client) write(line string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	_, err := c.conn.Write([]byte(line + "\r\n"))
	return err
}

// handshake registers and authenticates, reading the socket directly: the read
// loop only starts once the connection is usable.
func (c *Client) handshake(username, password string) error {
	br := bufio.NewReader(c.conn)
	c.conn.SetDeadline(time.Now().Add(handshakeLimit))
	defer c.conn.SetDeadline(time.Time{})

	read := func() (*Message, error) {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, fmt.Errorf("soju closed the connection during login: %w", err)
			}
			m, err := parseMessage(line)
			if err != nil {
				continue // ignore anything unparseable rather than failing login
			}
			if m.Command == "PING" {
				if err := c.write(formatMessage("PONG", m.Param(0))); err != nil {
					return nil, err
				}
				continue
			}
			return m, nil
		}
	}

	for _, l := range []string{
		"CAP LS 302",
		formatMessage("NICK", username),
		formatMessage("USER", username, "0", "*", "soju-webadmin"),
	} {
		if err := c.write(l); err != nil {
			return err
		}
	}

	// CAP LS may be split over several lines; "*" as the parameter before the
	// list means more are coming.
	sasl := false
	for {
		m, err := read()
		if err != nil {
			return err
		}
		if m.Command != "CAP" || m.Param(1) != "LS" {
			continue
		}
		last := m.Param(len(m.Params) - 1)
		for _, cap := range strings.Fields(last) {
			name, val, _ := strings.Cut(cap, "=")
			if name == "sasl" && (val == "" || strings.Contains(strings.ToUpper(val), "PLAIN")) {
				sasl = true
			}
		}
		if m.Param(2) != "*" {
			break
		}
	}
	if !sasl {
		return errors.New("soju did not offer SASL PLAIN, so this login cannot authenticate")
	}

	if err := c.write("CAP REQ :sasl soju.im/bouncer-networks batch message-tags"); err != nil {
		return err
	}
	for {
		m, err := read()
		if err != nil {
			return err
		}
		if m.Command == "CAP" && m.Param(1) == "NAK" {
			return errors.New("soju refused the capabilities this program needs")
		}
		if m.Command == "CAP" && m.Param(1) == "ACK" {
			break
		}
	}

	if err := c.write("AUTHENTICATE PLAIN"); err != nil {
		return err
	}
	for {
		m, err := read()
		if err != nil {
			return err
		}
		if m.Command != "AUTHENTICATE" {
			continue
		}
		payload := base64.StdEncoding.EncodeToString(
			[]byte("\x00" + username + "\x00" + password))
		if err := c.write("AUTHENTICATE " + payload); err != nil {
			return err
		}
		break
	}
	for {
		m, err := read()
		if err != nil {
			return err
		}
		switch m.Command {
		case "903": // SASL successful
			if err := c.write("CAP END"); err != nil {
				return err
			}
			goto registered
		case "902", "904", "905", "906":
			return errors.New("soju rejected these credentials")
		}
	}

registered:
	for {
		m, err := read()
		if err != nil {
			return err
		}
		if m.Command == "001" {
			// The MOTD that follows is left for the read loop to discard.
			return nil
		}
		if strings.HasPrefix(m.Command, "4") || strings.HasPrefix(m.Command, "5") {
			return fmt.Errorf("soju refused the connection: %s", m.Param(len(m.Params)-1))
		}
	}
}

func (c *Client) readLoop() {
	br := bufio.NewReader(c.conn)
	defer close(c.in)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		m, err := parseMessage(line)
		if err != nil {
			continue
		}
		if m.Command == "PING" {
			if err := c.write(formatMessage("PONG", m.Param(0))); err != nil {
				return
			}
			continue
		}
		select {
		case c.in <- m:
		default:
			// Nobody is collecting (or the buffer is full): unsolicited traffic is
			// not what this program is for, so it is dropped.
		}
	}
}

func (c *Client) Close() {
	c.conn.Close()
}

// Request sends lines and returns every message received before the PONG that
// closes the exchange.
func (c *Client) Request(lines ...string) ([]*Message, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	// Discard whatever arrived between requests, so the reply cannot be polluted
	// by, say, a network state change.
	for {
		select {
		case _, ok := <-c.in:
			if !ok {
				return nil, errClosed
			}
			continue
		default:
		}
		break
	}

	for _, l := range lines {
		if err := c.write(l); err != nil {
			return nil, err
		}
	}
	nonce := randToken(8)
	if err := c.write(formatMessage("PING", nonce)); err != nil {
		return nil, err
	}

	var out []*Message
	timeout := time.After(requestTimeout)
	for {
		select {
		case m, ok := <-c.in:
			if !ok {
				return nil, errClosed
			}
			if m.Command == "PONG" && (m.Param(0) == nonce || m.Param(1) == nonce) {
				return out, nil
			}
			out = append(out, m)
		case <-timeout:
			return nil, errors.New("soju did not answer in time")
		}
	}
}

// servQuote renders one BouncerServ argument. soju splits that line on spaces
// but honours double quotes, which is how arguments holding spaces — a realname,
// a raw line for `network quote` — survive the trip.
func servQuote(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\"\\") {
		return arg
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg) + `"`
}

// Serv runs a BouncerServ command and returns its reply, one line per element.
func (c *Client) Serv(args ...string) ([]string, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = servQuote(a)
	}
	msgs, err := c.Request(formatMessage("PRIVMSG", "BouncerServ", strings.Join(quoted, " ")))
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, m := range msgs {
		if m.Command != "PRIVMSG" && m.Command != "NOTICE" {
			continue
		}
		if !strings.EqualFold(m.Nick(), "BouncerServ") {
			continue
		}
		lines = append(lines, m.Param(len(m.Params)-1))
	}
	// BouncerServ reports failure as a single line opening with "error:".
	if len(lines) == 1 && strings.HasPrefix(strings.ToLower(lines[0]), "error:") {
		return nil, errors.New(strings.TrimSpace(lines[0][len("error:"):]))
	}
	if len(lines) == 0 {
		return nil, errors.New("BouncerServ did not answer")
	}
	return lines, nil
}

// ---------------------------------------------------------------- networks

// Network holds the attributes soju sent, untouched, so an attribute this
// program does not know about is still carried across an edit.
type Network struct {
	ID    string
	Attrs map[string]string
}

func (n *Network) Attr(k string) string { return n.Attrs[k] }

// Name is what BouncerServ calls this network. soju falls back to the address
// when a network was created without a name.
func (n *Network) Name() string {
	if v := n.Attrs["name"]; v != "" {
		return v
	}
	return n.Attrs["host"]
}

func (n *Network) State() string {
	if v := n.Attrs["state"]; v != "" {
		return v
	}
	return "unknown"
}

func (n *Network) Error() string { return n.Attrs["error"] }

// Addr rebuilds the ircs://host:port form that BouncerServ expects.
func (n *Network) Addr() string {
	scheme := "ircs"
	if n.Attrs["tls"] == "0" {
		scheme = "irc+insecure"
	}
	addr := scheme + "://" + n.Attrs["host"]
	if p := n.Attrs["port"]; p != "" {
		addr += ":" + p
	}
	return addr
}

func failError(msgs []*Message, verb string) error {
	for _, m := range msgs {
		if m.Command == "FAIL" && m.Param(0) == "BOUNCER" {
			return fmt.Errorf("%s", m.Param(len(m.Params)-1))
		}
	}
	return fmt.Errorf("soju did not confirm %s", verb)
}

func (c *Client) ListNetworks() ([]*Network, error) {
	msgs, err := c.Request("BOUNCER LISTNETWORKS")
	if err != nil {
		return nil, err
	}
	var nets []*Network
	for _, m := range msgs {
		if m.Command != "BOUNCER" || m.Param(0) != "NETWORK" {
			continue
		}
		attrs := m.Param(2)
		if attrs == "*" { // "*" marks a removal in the notify stream
			continue
		}
		nets = append(nets, &Network{ID: m.Param(1), Attrs: parseTags(attrs)})
	}
	return nets, nil
}

func (c *Client) Network(id string) (*Network, error) {
	nets, err := c.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		if n.ID == id {
			return n, nil
		}
	}
	return nil, fmt.Errorf("no network with id %q", id)
}

func (c *Client) AddNetwork(attrs map[string]string) (string, error) {
	msgs, err := c.Request("BOUNCER ADDNETWORK " + formatTags(attrs))
	if err != nil {
		return "", err
	}
	for _, m := range msgs {
		if m.Command == "BOUNCER" && m.Param(0) == "ADDNETWORK" {
			return m.Param(1), nil
		}
	}
	return "", failError(msgs, "the new network")
}

// ChangeNetwork updates attributes. An empty value clears an attribute, which
// is how the extension expresses "unset".
func (c *Client) ChangeNetwork(id string, attrs map[string]string) error {
	msgs, err := c.Request("BOUNCER CHANGENETWORK " + id + " " + formatTags(attrs))
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Command == "FAIL" && m.Param(0) == "BOUNCER" {
			return errors.New(m.Param(len(m.Params) - 1))
		}
	}
	return nil
}

func (c *Client) DeleteNetwork(id string) error {
	msgs, err := c.Request("BOUNCER DELNETWORK " + id)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Command == "FAIL" && m.Param(0) == "BOUNCER" {
			return errors.New(m.Param(len(m.Params) - 1))
		}
	}
	return nil
}

// ---------------------------------------------------------------- channels

type Channel struct {
	Name    string
	Network string
	Status  string // as printed by soju: "joined", "joined, detached", …
}

func (ch *Channel) Detached() bool { return strings.Contains(ch.Status, "detached") }
func (ch *Channel) Joined() bool   { return strings.Contains(ch.Status, "joined") }

// Channels lists saved channels. With an empty network it covers every network
// and soju appends "/network" to each name — that suffix is how the dashboard
// tells them apart. Asked about one network, soju leaves the name bare.
func (c *Client) Channels(network string) ([]*Channel, error) {
	args := []string{"channel", "status"}
	if network != "" {
		args = append(args, "-network", network)
	}
	lines, err := c.Serv(args...)
	if err != nil {
		return nil, err
	}
	var out []*Channel
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "No channel configured." {
			continue
		}
		name, status := l, ""
		if i := strings.LastIndex(l, " ["); i >= 0 {
			name, status = l[:i], strings.TrimSuffix(l[i+2:], "]")
		}
		net := network
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name, net = name[:i], name[i+1:]
		}
		out = append(out, &Channel{Name: name, Network: net, Status: status})
	}
	return out, nil
}

// ---------------------------------------------------------------- users

type User struct {
	Name string
	Line string // the whole line as soju printed it
}

func (c *Client) Users() ([]*User, error) {
	lines, err := c.Serv("user", "status")
	if err != nil {
		return nil, err
	}
	var out []*User
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		name := l
		if i := strings.IndexAny(name, " :("); i >= 0 {
			name = name[:i]
		}
		out = append(out, &User{Name: name, Line: l})
	}
	return out, nil
}
