# Snippy

[![CI](https://github.com/jvantuyl/snippy/actions/workflows/ci.yml/badge.svg)](https://github.com/jvantuyl/snippy/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/snippy.svg)](https://hex.pm/packages/snippy)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/snippy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Discover SSL certificates and keys from environment variables and produce
ready-to-use configuration for `:ssl.listen/2`, Cowboy, Ranch, Bandit, or
Thousand Island.

Snippy turns 12-factor-style env vars (`MYAPP_API_CRT`, `MYAPP_API_KEY`, ...)
into a fully-validated, hot-reloadable cert store with built-in SNI, multi-cert
per host (e.g. ECDSA + RSA), optional public-CA chain validation, optional
OCSP stapling hints, and a `:sni_fun` you can hand straight to your TLS
listener.

The name and design were inspired by the TLS [Server Name Indication
(SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) extension:
Snippy's whole reason to exist is to make it trivial to serve the right
certificate for the right hostname out of a single listener.

## Why

Snippy was originally written to put HTTPS on the origin side of a
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
*without* falling back to `noTLSVerify: true`. Cloudflare issues free
[Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
certificates that `cloudflared` can verify against the Cloudflare Origin
Root CA via the
[`caPool` / `originServerName`](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
tunnel parameters. Combine that with a Phoenix or Bandit endpoint and the
only piece left was: how do you actually get those PEM blobs into the BEAM
TLS listener as decoded `:certs_keys` and an `:sni_fun`, ideally hot-reloadable
when the cert is rotated, and ideally without sprinkling `File.read!/1` calls
through your `runtime.exs`?

That's Snippy.

More generally: container platforms inject secrets as files or environment
variables, but TLS listeners want decoded DER, key records, and an `:sni_fun`
callback. Snippy bridges that gap. You give it a prefix; it does the rest.

## Installation

The package is available on [Hex](https://hex.pm/packages/snippy) and can be
installed by adding `snippy` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:snippy, "~> 0.6.0"},
    # Optional: enables public-CA chain validation against the
    # Mozilla CA bundle shipped with castore.
    {:castore, "~> 1.0"}
  ]
end
```

Documentation is generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). The docs can be found at
<https://hexdocs.pm/snippy>.

The latest CI build also publishes documentation and a test-coverage report
to GitHub Pages:

- Docs: <https://jvantuyl.github.io/snippy/>
- Coverage: <https://jvantuyl.github.io/snippy/coverage/>

## Quick Start

Set environment variables for one or more certificates, all sharing a common
prefix:

```sh
export MYAPP_API_CRT_FILE=/run/secrets/api.crt.pem
export MYAPP_API_KEY_FILE=/run/secrets/api.key.pem

export MYAPP_ADMIN_CRT_FILE=/run/secrets/admin.crt.pem
export MYAPP_ADMIN_KEY_FILE=/run/secrets/admin.key.pem
export MYAPP_ADMIN_PASSWORD_FILE=/run/secrets/admin.key.password
```

Each helper takes the prefix directly. The shared `Snippy.Store` does the
env scan once on first use and caches both successes and failures, so calls
are cheap to repeat.

```elixir
# Plug.Cowboy
Plug.Cowboy.https(
  MyAppWeb.Endpoint,
  [],
  [port: 4443] ++ Snippy.cowboy_opts(prefix: "MYAPP")
)

# Bandit
Bandit.start_link(
  [plug: MyAppWeb.Endpoint, scheme: :https]
  ++ Snippy.bandit_opts(prefix: "MYAPP")
)

# Thousand Island
ThousandIsland.start_link(
  [port: 4443, handler_module: MyHandler]
  ++ Snippy.thousand_island_opts(prefix: "MYAPP")
)

# Ranch
:ranch.start_listener(
  :https,
  :ranch_ssl,
  Snippy.ranch_opts(prefix: "MYAPP"),
  MyProtocol,
  []
)

# Plain :ssl
{:ok, listen_socket} = :ssl.listen(4443, Snippy.ssl_opts(prefix: "MYAPP"))
```

For Phoenix endpoints, use `phx_endpoint_config/1` directly in your runtime
config:

```elixir
# config/runtime.exs
config :my_app, MyAppWeb.Endpoint,
  https:
    Snippy.phx_endpoint_config(
      prefix: "MYAPP",
      port: 4443,
      cipher_suite: :strong
    )
```

The result already includes both `:certs_keys` (for clients that don't
send SNI) and `:sni_fun` (for clients that do). Multiple certs whose
hostnames overlap are returned together so OTP can pick the one that
matches the client's key-exchange algorithm.

## How Discovery Works

Snippy is built around the principle that work should happen exactly once,
and only when it's needed. Three lazy phases sit behind every helper call:

1. **Scan** (cheap, shared). On first use, `Snippy.Store` walks the entire
   environment and records every variable whose name ends in a recognized
   suffix (`_CRT`, `_KEY`, `_PWD`, ...). No PEM is decoded, no files are
   read. This scan is shared across every helper call across every prefix.

2. **Filter by prefix** (per call). Each helper takes the broad scan
   results and peels off entries whose names start with the requested
   prefix. This costs one pass over the in-memory scan list - cheap, and
   no rescan is required when adding new helpers or new prefixes.

3. **Materialize** (lazy, per group). Only when a helper actually asks
   about a `(prefix, key)` group does Snippy decode PEM, decrypt keys,
   verify the cert/key match, check expiry, and build the final `:ssl`
   payload. Successes *and* errors are memoized in ETS, so repeated
   lookups are constant-time and broken groups don't spam the log on
   every request.

This shape gives Snippy a small DoS surface: env vars that no helper ever
asks about never get decoded, even if an attacker can set arbitrary
environment variables in the process.

### Pre-warming and the `:discovered_certs` escape hatch

Most apps don't need to think about when materialization happens - the
first inbound TLS handshake will pay for it once and every subsequent one
will reuse the cache. If you want to control timing explicitly (e.g. fail
fast at boot if a cert is bad), call `Snippy.discover_certificates/1`
during application start. It returns a `%Snippy.Discovery{}` handle whose
`:groups` is the successfully materialized set and whose `:errors`
contains any per-group failures:

```elixir
{:ok, disc} = Snippy.discover_certificates(prefix: "MYAPP")

if disc.errors != [] do
  raise "snippy: bad certs at boot: #{inspect(disc.errors)}"
end
```

You can also pass the handle into any helper via `:discovered_certs` to
make a particular call use *that* discovery's groups instead of the
shared store:

```elixir
Snippy.cowboy_opts(prefix: "MYAPP", discovered_certs: disc)
```

This is mainly useful when running tests with a custom `:env` or when you
want a cert set pinned to one specific scan generation.

## Environment-Variable Conventions

Snippy looks at every env var that begins with the configured `:prefix`,
followed by an underscore, then a free-form *key*, then a recognized
*suffix*:

```
<PREFIX>_<KEY>_<SUFFIX>
```

For `prefix: "MYAPP"`, `MYAPP_API_CRT_FILE` decomposes as:

| segment | value |
| --- | --- |
| prefix | `MYAPP` |
| key | `API` |
| suffix | `_CRT_FILE` |

All vars sharing the same `(prefix, key)` form one *group*, which represents a
single (cert, key, optional CA, optional password) bundle.

### Recognized Suffixes

| Suffix | Purpose |
| --- | --- |
| `_CRT` | Inline PEM-encoded certificate (or chain) |
| `_CRT_FILE` | Path to a PEM-encoded certificate (or chain) |
| `_KEY` | Inline PEM-encoded private key (PKCS#1, SEC1, or PKCS#8; encrypted or not) |
| `_KEY_FILE` | Path to a PEM-encoded private key |
| `_PWD`, `_PASS`, `_PASSWD`, `_PASSWORD` | Inline password for an encrypted key |
| `_PWD_FILE`, `_PASS_FILE`, `_PASSWD_FILE`, `_PASSWORD_FILE` | Path to a password file |
| `_CACRT` | Inline PEM-encoded CA chain (intermediates, root last) |
| `_CACRT_FILE` | Path to a PEM-encoded CA chain |
| `_OCSP_STAPLING` | Boolean flag (`true`/`false`/`on`/`off`/`1`/`0`/...) |
| `_OSCP_STAPLING` | Common typo; honored with a warning |

Snippy raises if more than one password alias is set on the same group, so
you don't end up wondering which one took effect.

### Multiple Prefixes

`:prefix` accepts a string, an atom, or a list of either. Snippy raises if
one prefix is a strict prefix of another (e.g. `["MY", "MYAPP"]`) so that
matching is unambiguous.

## Public API

```elixir
{:ok, disc} = Snippy.discover_certificates(opts)
{:ok, disc} = Snippy.reload(disc)

sni_fun     = Snippy.sni(opts)
ssl_opts    = Snippy.ssl_opts(opts)
cowboy_opts = Snippy.cowboy_opts(opts)
ranch_opts  = Snippy.ranch_opts(opts)
bandit_opts = Snippy.bandit_opts(opts)
ti_opts     = Snippy.thousand_island_opts(opts)
phx_opts    = Snippy.phx_endpoint_config(opts)
```

All helpers accept the same option groups (each is optional unless noted):

### Required

| Option | Description |
| --- | --- |
| `:prefix` | String, atom, or list of either |

### Discovery passthrough

| Option | Default | Description |
| --- | --- | --- |
| `:case_sensitive` | `true` | Match env-var names case-sensitively |
| `:env` | `System.get_env()` | Env map override (mainly for testing) |
| `:reload_interval_ms` | `nil` | If set, the Store schedules background re-scans at this cadence |

### Per-lookup

| Option | Default | Description |
| --- | --- | --- |
| `:default_hostname` | `nil` | Hostname used to seed `:certs_keys` for non-SNI clients |
| `:expiry_grace_seconds` | `0` | Tolerate certs that expired up to this many seconds ago |
| `:public_ca_validation` | `:auto` | `:auto`, `:always`, or `:never` (see below) |
| `:only` | `nil` | List of hostname patterns; only matching groups are exposed |
| `:keys` | `nil` | List of group key strings (or atoms); only matching groups are exposed |

`:only` and `:keys` are unioned: a group is included if it matches either.

### Escape hatch

| Option | Default | Description |
| --- | --- | --- |
| `:discovered_certs` | `nil` | A `%Snippy.Discovery{}` from `discover_certificates/1`. When set, the helper uses *that* discovery and skips the shared Store entirely. |

## Validation Pipeline

For each discovered group, Snippy runs a series of checks before adding it
to the live cert store. Failed groups are dropped with a logged error.

1. **PEM decoding.** Both inline and `_FILE` sources are decoded inside
   Snippy; encrypted PKCS#8 keys are decrypted using the supplied password.
   The password is tried trimmed first, then untrimmed, to forgive trailing
   newlines from `_FILE` sources.
2. **Cert/key match.** Snippy signs a probe message with the private key
   and verifies it against the SubjectPublicKeyInfo from the certificate.
   This works for RSA, ECDSA, and EdDSA in any PEM form.
3. **Validity window.** `notBefore` and `notAfter` are checked against the
   current time. `:expiry_grace_seconds` extends the upper bound only.
4. **Chain validation.**
   - If a `_CACRT*` is provided, it's used as the trust anchor.
   - Otherwise, if `castore` is loaded, the leaf is checked against the
     Mozilla bundle.
   - Otherwise the cert is accepted as self-signed (with an info-level log).
   - `:public_ca_validation` controls strictness:
     - `:auto` (default) - try `castore` if available, accept failures.
     - `:always` - require successful public-CA validation, drop on failure.
     - `:never` - skip public-CA validation entirely.

## SNI and Multi-Cert Per Host

Snippy stores one row per (hostname, group) in a public ETS bag. When
multiple groups advertise the same hostname (e.g. an ECDSA cert and an RSA
fallback for `api.example.com`), the SNI fun returns all matching
`certs_keys` so OTP can choose based on the client's signature algorithm.

Wildcard certs (leftmost-label `*` only) are matched using
[domainname](https://hex.pm/packages/domainname) for correctness.

## Reloading

```elixir
{:ok, disc} = Snippy.reload(disc)
```

`reload/1` re-scans the environment and re-reads every `_FILE` source. If no
group in the discovery has any `_FILE` source, a warning is logged - reload
would do nothing, since inline values come from the OS env at boot.

`:reload_interval_ms` schedules background reloads at the requested cadence.
Background reload errors are logged and the previous good state is retained.

## Supervisor Restart Tuning

Snippy's supervision tree uses a `:one_for_all` strategy. Under heavy load,
transient validation or filesystem errors during a reload can cause the
store to crash; if those crashes happen too quickly the supervisor will
itself give up.

The default restart budget tolerates roughly a 20% failure rate on a server
handling 50 requests per second over a 15-second window (about 150 failures).
You can tune both bounds via application config:

```elixir
# config/runtime.exs
config :snippy,
  max_restarts: 150,
  max_seconds: 15
```

## Diagnostics

```sh
mix snippy.test --prefix MYAPP
```

`mix snippy.test` runs the same discovery pipeline and prints what Snippy
saw, what it accepted, and what it rejected (and why). Passwords are
elided from output.

## Requirements

- Elixir 1.19+
- Erlang/OTP 25+ (Snippy enforces this both at compile time and at startup)

## License

[MIT](LICENSE.md). Copyright (c) 2026 Jayson Vantuyl.
