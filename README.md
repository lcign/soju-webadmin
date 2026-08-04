# soju-webadmin

A web interface for the [soju](https://codeberg.org/emersion/soju) IRC bouncer, in the spirit of
ZNC's webadmin: networks, channels, SASL, users — without typing BouncerServ commands.

Single Go binary, no dependencies, no database, no build step. Templates, stylesheet and the one
small script are embedded in the binary.

**Users sign in with their soju credentials.** There are no accounts of its own: the login is a SASL
PLAIN authentication against soju, and everything afterwards happens as that user, with that user's
permissions. Admins additionally get the user management pages.

## What it does

- **Networks** — add, edit, enable/disable, delete, with connection state and the last error.
- **Channels** — join and leave, detach and attach, per-channel notification filters.
- **SASL PLAIN** per network, and **client certificates** (certfp) with the fingerprint to register.
- **Raw lines** to a network, the same as `network quote` — handy for HostServ and friends.
- **Console** for any BouncerServ command, with its reply.
- **Users** (admins) — create, edit, delete, and broadcast a notice.
- **A watcher** for the two things soju does not do for itself: see below.

## The watcher

`soju-webadmin -watch` is the same binary doing a different job, on a timer:

**Zombie connections.** soju can hold a network as `connected` while the socket on the other side is
dead: the state says connected, the channels are listed, and nothing sent to that network arrives
anywhere. The check is a `WHOIS` sent **through soju** on a connection bound to that network. A live
upstream answers `311` or `401`; a dead one answers nothing, so the timeout is the diagnosis. Two
silent probes in a row force a reconnect — one lagged server should not be enough — and an alert goes
out.

**Keeping your nick.** soju's connect commands only run when a connection registers, so after a
netsplit, where nothing reconnects, a nick lost to a ghost stays lost. The escalation is what a person
would do, one step per pass: plain `NICK`, then the network's services, then identify first. After
three failures it waits an hour, because by then the nick may simply belong to somebody else.

Everything goes through soju — raw lines, as `network quote` does — so it never writes to soju's
database and never opens a second connection to the remote network.

```sh
install -Dm600 contrib/watch.conf.example /etc/soju-webadmin/watch.conf   # then edit it
soju-webadmin -watch -watch-once -watch-dry-run   # rehearse: changes nothing, leaves no state
install -m644 contrib/soju-webadmin-watch.{service,timer} /etc/systemd/system/
systemctl enable --now soju-webadmin-watch.timer
```

`-watch-once` does a single pass and exits, for a systemd timer or cron; without it the watcher stays
up and paces itself with `interval`. Alerts are handed to `alert-command` on stdin (`msmtp
you@example.org`, `mail -s …`); with none configured they only reach the log.

⚠️ The watcher signs in as a soju user, so its configuration holds that password and is refused
unless it is mode 0600. This is the one thing it needs that the web interface does not.

## Install

```sh
go build -o soju-webadmin .
./soju-webadmin -soju localhost:6697
```

It then serves on `http://127.0.0.1:8080/`. Options:

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | address to serve on |
| `-soju` | `localhost:6697` | soju's address |
| `-soju-plaintext` | off | talk to soju without TLS — only sane over loopback |
| `-soju-insecure` | off | accept soju's certificate unverified (self-signed setups) |
| `-base-path` | | serve under a sub-path, e.g. `/soju` |
| `-tls-cert`, `-tls-key` | | serve HTTPS directly instead of behind a proxy |
| `-secure-cookie` | off | mark the session cookie `Secure`; set this behind an HTTPS proxy |
| `-idle-timeout` | `1h` | close a session after this long without a request |

soju needs a listener this program can reach — the normal `listen ircs://…` one is enough:

```
listen ircs://0.0.0.0:6697
```

Behind a reverse proxy, terminate TLS there, pass the requests through, and add `-secure-cookie`:

```nginx
location /soju/ {
    proxy_pass http://127.0.0.1:8080/soju/;
}
```

With Docker:

```sh
docker build -t soju-webadmin .
docker run --rm -p 8080:8080 soju-webadmin -listen 0.0.0.0:8080 -soju host.docker.internal:6697
```

## How it talks to soju

Two interfaces, for two reasons:

- **Networks** go through the `soju.im/bouncer-networks` extension — a structured protocol with
  attribute lists and numeric ids, the same one gamja uses. Nothing is scraped.
- **Everything else** goes through **BouncerServ**, whose replies are lines of prose. They are shown
  as they arrive wherever that is enough, and parsed only where the interface needs the fields
  (channel names and their status, user names).

soju does not implement `labeled-response`, so replies cannot be tagged and matched to a request.
Instead each request takes a lock, sends its command, then sends a `PING` carrying a nonce: IRC is
ordered per connection, so by the time the matching `PONG` arrives, every line belonging to the
command has arrived too.

⚠️ That trick holds **only for what soju answers itself**. Anything relayed to a network — the
watcher's `WHOIS` — comes back later than soju's own `PONG`, so those wait for the reply they expect,
with a timeout of their own. Mixing the two up makes a live network look dead.

A connection bound to a network must also declare `draft/chathistory`, or soju replays the stored
backlog to it. For a watchdog binding once per pass, that would mean dragging history across the
socket every time.

One IRC connection is held per signed-in session and closed when the session goes idle. If soju
restarts, the next request redials and retries once, so nobody is logged out.

## Limits worth knowing

- **Parsing prose.** The BouncerServ side depends on soju's wording. A future soju can change it;
  when that happens, the affected field stops being read, and the console keeps working regardless.
  Tested against soju **0.10.1**.
- **Nameless networks.** soju addresses a network without a name by its stored address, which this
  program cannot always reconstruct from the attributes it is given. Such a network is flagged, and
  giving it a name fixes it.
- **Per-network extras** that soju exposes only as write-only flags — `auto-away`, `ignore-limit`,
  `connect-command` — have no field of their own, since their current value cannot be read back.
  Set them from the console.
- **The session holds your soju password in memory** for the lifetime of the session, so it can
  redial. Nothing is written to disk; there is no state to steal after the process exits.
- **The watcher counts as a client.** It binds to a network for a moment on every pass, which is
  enough to clear soju's `auto-away` on that network until it disconnects again.
- **`BOUNCER BIND` is registration-time only**, so the watcher binds through the SASL username
  (`user/network`) instead. Its connections are named (`@watch`) to keep their state apart from your
  real clients.
- Not a chat client. Reading and writing messages is what gamja, goguma and senpai are for.

## License

MIT, see [LICENSE](LICENSE). soju itself is AGPL-3.0 and is not included here.
