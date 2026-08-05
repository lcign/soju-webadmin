# soju-webadmin

A web interface for the [soju](https://codeberg.org/emersion/soju) IRC bouncer, in the spirit of
ZNC's webadmin. Single Go binary, no dependencies, no database, no build step.

**You sign in with your soju credentials** — the login is a SASL PLAIN authentication against soju,
and everything after it happens as that user. No accounts of its own.

- Networks: add, edit, enable, delete, with state and last error
- Channels: join, leave, detach, notification filters
- SASL PLAIN and client certificates, per network
- Raw lines to a network, and a console for any BouncerServ command
- Users, for admins
- A watcher for zombie connections and lost nicks
- English and Italian

⚠️ What soju answers stays in soju's words: BouncerServ replies, channel and SASL status, its errors.

## Install

```sh
go build -o soju-webadmin .
./soju-webadmin -soju localhost:6697      # serves on http://127.0.0.1:8080/
```

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | address to serve on |
| `-soju` | `localhost:6697` | soju's address |
| `-soju-plaintext` | off | no TLS to soju — only sane over loopback |
| `-soju-insecure` | off | accept soju's certificate unverified |
| `-base-path` | | serve under a sub-path, e.g. `/soju` |
| `-tls-cert`, `-tls-key` | | serve HTTPS directly |
| `-secure-cookie` | off | mark the session cookie `Secure`, behind an HTTPS proxy |
| `-idle-timeout` | `1h` | close an idle session |
| `-lang` | `en` | preferred language; browser and reader still choose |
| `-locales-dir` | | translations from a directory instead of the built-in ones |
| `-watch-state-dir` | `/var/lib/soju-webadmin` | the watcher's state and log |
| `-watch-policy` | | the watcher's policy file; makes it editable in the interface |

The usual `listen ircs://…` in soju is enough. Behind a reverse proxy, terminate TLS there, pass
requests through, and add `-secure-cookie`.

## The watcher

`soju-webadmin -watch` does two things soju does not do for itself:

- **zombie connections** — soju can hold a network as connected while the socket on the other side is
  dead. A `WHOIS` through soju answers on a live one and never returns on a dead one, so the timeout
  is the diagnosis; two in a row force a reconnect and send an alert.
- **a lost nick** — connect commands only run at registration, so a nick lost to a netsplit stays
  lost. Same escalation a person would do, one step per pass, then an hour's pause.

```sh
install -Dm600 contrib/watch.conf.example /etc/soju-webadmin/watch.conf   # then edit it
soju-webadmin -watch -watch-once -watch-dry-run                           # rehearse, changes nothing
install -m644 contrib/soju-webadmin-watch.{service,timer} /etc/systemd/system/
systemctl enable --now soju-webadmin-watch.timer
```

⚠️ It signs in as a soju user, so its configuration holds that password and is refused unless it is
mode 0600. The **policy** — which networks to skip, what to send their services — belongs in a
separate file (`-watch-policy`) the interface may edit; credentials never go there.

The *Watcher* page shows its state and log, and a **Check now** that runs the same probe on your own
connection, changing nothing. Admins only.

`contrib/soju-webadmin-update` updates a container and a host binary from one build, extracting the
binary from the image so the two copies cannot drift.

## Translations

Copy `locales/en.json`, translate the values, name it after the language tag, open a pull request —
no Go changes, catalogs are found by filename. `_name` is the language in its own words, `{name}` are
placeholders to keep, `.one`/`.other` are plural forms. Missing keys fall back to English, so a
partial translation is welcome.

```sh
soju-webadmin -locales-dir ./locales    # try one without rebuilding
go test ./...                           # no key missing, none invented
```

## Notes

- Networks go through the `soju.im/bouncer-networks` extension; everything else through BouncerServ,
  whose replies are prose and are parsed only where a field is needed. Tested against soju **0.10.1**.
- A network without a name is addressed by its stored address and may not resolve: give it one.
- `auto-away`, `ignore-limit` and `connect-command` are write-only in soju, so they have no field —
  set them from the console.
- The session keeps your soju password in memory to redial; nothing is written to disk.
- Not a chat client: that is what gamja, goguma and senpai are for.

Why anything is done the way it is: the code says so, where it matters.

## License

MIT, see [LICENSE](LICENSE). soju itself is AGPL-3.0 and is not included here.
