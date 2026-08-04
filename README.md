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
- Not a chat client. Reading and writing messages is what gamja, goguma and senpai are for.

## License

MIT, see [LICENSE](LICENSE). soju itself is AGPL-3.0 and is not included here.
