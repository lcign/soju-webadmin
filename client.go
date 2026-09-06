package main

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

type ServerConfig struct {
	Addr     string
	TLS      bool
	Insecure bool
}

type Client struct {
	cfg ServerConfig

	conn net.Conn
	in   chan *Message

	wmu sync.Mutex
	rmu sync.Mutex

	Username string
	IsAdmin  bool
	Nick     string
}

type dialOpts struct {
	network string

	client string

	caps []string
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {

		panic(err)
	}
	return hex.EncodeToString(b)
}

func Dial(cfg ServerConfig, username, password string) (*Client, error) {
	return dial(cfg, username, password, dialOpts{})
}

func dial(cfg ServerConfig, username, password string, o dialOpts) (*Client, error) {
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
	if err := c.handshake(username, password, o); err != nil {
		conn.Close()
		return nil, err
	}
	go c.readLoop()

	if o.network == "" {

		if _, err := c.Serv("user", "status"); err == nil {
			c.IsAdmin = true
		}
	}
	return c, nil
}

func saslUsername(user string, o dialOpts) string {
	s := user
	if o.client != "" {
		s += "@" + o.client
	}
	if o.network != "" {
		s += "/" + o.network
	}
	return s
}

func (c *Client) write(line string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	_, err := c.conn.Write([]byte(line + "\r\n"))
	return err
}

func (c *Client) handshake(username, password string, o dialOpts) error {
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
				continue
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

	caps := append([]string{"sasl", "soju.im/bouncer-networks", "batch", "message-tags"}, o.caps...)
	if err := c.write("CAP REQ :" + strings.Join(caps, " ")); err != nil {
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
			[]byte("\x00" + saslUsername(username, o) + "\x00" + password))
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
		case "903":
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

			c.Nick = m.Param(0)

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

		}
	}
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Request(lines ...string) ([]*Message, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

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

func (c *Client) Send(line string) error {
	return c.write(line)
}

func (c *Client) Await(line string, want []string, timeout time.Duration) ([]*Message, bool, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	for {
		select {
		case _, ok := <-c.in:
			if !ok {
				return nil, false, errClosed
			}
			continue
		default:
		}
		break
	}

	if err := c.write(line); err != nil {
		return nil, false, err
	}

	wanted := make(map[string]bool, len(want))
	for _, cmd := range want {
		wanted[cmd] = true
	}

	var out []*Message
	deadline := time.After(timeout)
	for {
		select {
		case m, ok := <-c.in:
			if !ok {
				return out, false, errClosed
			}
			out = append(out, m)
			if wanted[m.Command] {
				return out, true, nil
			}
		case <-deadline:
			return out, false, nil
		}
	}
}

func servQuote(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\"\\") {
		return arg
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg) + `"`
}

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

	if len(lines) == 1 && strings.HasPrefix(strings.ToLower(lines[0]), "error:") {
		return nil, errors.New(strings.TrimSpace(lines[0][len("error:"):]))
	}
	if len(lines) == 0 {
		return nil, errors.New("BouncerServ did not answer")
	}
	return lines, nil
}

type Network struct {
	ID    string
	Attrs map[string]string
}

func (n *Network) Attr(k string) string { return n.Attrs[k] }

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
		if attrs == "*" {
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

type Channel struct {
	Name    string
	Network string
	Status  string
}

func (ch *Channel) Detached() bool { return strings.Contains(ch.Status, "detached") }
func (ch *Channel) Joined() bool   { return strings.Contains(ch.Status, "joined") }

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

type User struct {
	Name string
	Line string
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
