# Snippy

[![CI](https://github.com/jvantuyl/snippy/actions/workflows/ci.yml/badge.svg)](https://github.com/jvantuyl/snippy/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/snippy.svg)](https://hex.pm/packages/snippy)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/snippy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Discover SSL certificates and keys from environment variables and produce
ready-to-use configuration for many popular TLS endpoints (i.e.
`:ssl.listen/2`, Cowboy, Ranch, Bandit, ThousandIsland, etc.).

Snippy turns 12-factor-style env vars (`MYAPP_API_CRT`, `MYAPP_API_KEY`, ...)
into a fully-validated, hot-reloadable cert store with built-in SNI, multi-cert
per host (e.g. ECDSA + RSA), optional public-CA chain validation, and a
`:sni_fun` you can hand straight to your TLS listener.

The name was inspired by the TLS [Server Name Indication
(SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) extension that is
used to allow multiple certificates on a single endpoint.

## Requirements

- Elixir 1.19+
- Erlang/OTP 25+ (Snippy enforces this both at compile time and at startup)

## Installation

The package is available on [Hex](https://hex.pm/packages/snippy) and can be
installed by adding `snippy` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:snippy, "~> 0.8.3"},
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

Collect your certificates and keys.  Choose a global prefix you'll use to make
them easy to find.  For each one, choose an identifying "key" that shows they
go together.  Choose appropriate suffixes to indicate which parameter the
variable represents.

Combine all that together into some variables like this:

```sh
export MYAPP_API_CRT_FILE=/run/secrets/api.crt.pem
export MYAPP_API_KEY_FILE=/run/secrets/api.key.pem

export MYAPP_ADMIN_CRT_FILE=/run/secrets/admin.crt.pem
export MYAPP_ADMIN_KEY_FILE=/run/secrets/admin.key.pem
export MYAPP_ADMIN_PASSWORD_FILE=/run/secrets/admin.key.password
```

Test them with this `Mix` task:

```sh
mix snippy.test --prefix MYAPP
```

If you see your keys, they're being discovered!

Now use the helper for your framework of choice to configure it:

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

For Phoenix endpoints, you can even use `phx_endpoint_config/1` directly in
your runtime config:

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

The produced configuration comes with both `:certs_keys` (for clients that
don't send SNI) and `:sni_fun` (for clients that do). Multiple certs whose
hostnames overlap are returned together so OTP can pick the one that matches
the client's key-exchange algorithm.

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
| suffix | `CRT_FILE` |

All vars sharing the same `(prefix, key)` form one *group*, which represents a
single (cert, key, optional CA, optional password) bundle.

When multiple certificates cover the same domain names, Snippy configures both
of them.  This is how to provide certificates for two completely different key
types (i.e. ECDSA falling back to RSA).

### Recognized Suffixes

Suffixes correspond to the options normally used to configure TLS endpoints in
Elixir:

| TLS Option | Suffix | Purpose |
| --- | --- |
| `:cert` | `CRT`, `CERT` | Inline PEM-encoded certificate (or chain) |
| `:certfile` | `CRT_FILE`, `CERT_FILE` | Path to a PEM-encoded certificate (or chain) |
| `:key` | `KEY` | Inline PEM-encoded private key (PKCS#1, SEC1, or PKCS#8; encrypted or not) |
| `:keyfile` | `KEY_FILE` | Path to a PEM-encoded private key |
| `:password` | `PWD`, `PASS`, `PASSWD`, `PASSWORD` | Inline password for an encrypted key |
| none | `PWD_FILE`, `PASS_FILE`, `PASSWD_FILE`, `PASSWORD_FILE` | Path to a password file |
| `:cacerts` | `CACRT`, `CACERT` | Inline PEM-encoded CA chain (intermediates, root last) |
| `:cacertfile` | `CACRT_FILE`, `CACERT_FILE` | Path to a PEM-encoded CA chain |

Snippy raises if more than one alias is set for the same option on the same
group, so you don't end up wondering which one took effect.

### Multiple Prefixes

`:prefix` accepts a string, an atom, or a list of either. Snippy raises if
one prefix is a strict prefix of another (e.g. `["MY", "MYAPP"]`) so that
matching is unambiguous.

## Public API

```elixir
{:ok, discovered_certs} = Snippy.reload(opts)

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

### Discovery Settings

| Option | Default | Description |
| --- | --- | --- |
| `:case_sensitive` | `true` | Match env-var names case-sensitively |
| `:env` | `System.get_env()` | Env map override (mainly for testing) |
| `:reload_interval_ms` | `nil` | If set, the Store schedules background re-scans at this cadence |

### Lookup Settings

| Option | Default | Description |
| --- | --- | --- |
| `:default_hostname` | `nil` | Hostname used to seed `:certs_keys` for non-SNI clients |
| `:expiry_grace_seconds` | `0` | Tolerate certs that expired up to this many seconds ago |
| `:public_ca_validation` | `:auto` | `:auto`, `:always`, or `:never` (see below) |
| `:only` | `nil` | List of hostname patterns; only matching groups are exposed |
| `:keys` | `nil` | List of group key strings (or atoms); only matching groups are exposed |

`:only` and `:keys` are unioned: a group is included if it matches either.

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

When multiple groups advertise the same hostname (e.g. an ECDSA cert and an RSA
fallback for `api.example.com`), the SNI fun returns all matching `certs_keys`
so OTP can choose based on the client's signature algorithm.

Wildcard certs (leftmost-label `*` only) are matched using
[domainname](https://hex.pm/packages/domainname) for correctness.

## Reloading

```elixir
{:ok, discovered_certs} = Snippy.reload()
```

`reload/1` re-scans the environment and re-reads every `_FILE` source. If no
group in the discovery has any `_FILE` source, a warning is logged - reload
would do nothing, since inline values come from the OS env at boot.

Environmental variables are generally not changed once an application is
loaded, so we don't check non-file variables.  If there is a compelling reason,
this may be changed in the future.

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


## Why

It all started with a
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/).
What I wanted seemed simple--HTTPS all the way to my application.  I also
wanted to use something better than just a self-signed certificate.

I quickly discovered that Cloudflare issues free
[Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
certificates.  `cloudflared` can verify these certificates against their own
Cloudflare Origin Root CA.  This seemed ideal.  Should be easy, right?

I started by wiring everything together and immediately hit another problem.  I
didn't want to store the secret information on disk.  I wanted it in the
environment.  It was here I hit my first obstacle: Bandit (and thus Phoenix)
didn't have a good way to give it key data that wasn't on disk.

For the time being, I put the secrets on disk--figuring that my first goal
(end-to-end encryption in transit) was the harder one to achieve.  Still, I
kept that item on my to-do list.

It so happens that I am serving the same site from two different domains.  Next
I discovered that Cloudflare won't put the different domains on the same
certificate, so I needed to create two.

Then I discovered that configuring Bandit (and thus Phoenix) with both of these
certificates was not really well documented and could possibly be done no less
than four different ways--each of them rather tedious and fiddly.  I did
discover how to provide information without writing files, so I had a solution
to my to-do item.

After figuring out the correct syntax to get everything to work together, I
fired up the tunnel.  It had previously worked with HTTP, so I figured HTTPS
would just be a simple change.  Immediately, the tunnel started giving errors
mentioning that `localhost` didn't match the name on the certificate.

Looking around, all of the advice out there was to turn off TLS-verification.
That kind of defeats the point, so I kept digging.  I eventually prevailed by
setting the
[`caPool` / `originServerName`](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
tunnel parameters.

Now it was working, but this all seemed *way* more complicated than it needed
to be.  I have the certificates, they have the names in them.  I just want to
find them in environmental variables and configure one of my TLS endpoints with
them.

Thus, Snippy was born.  It provides the plumbing from environmental variables
(and possibly files) all the way to the parameters for your favorite framework.

## License

[MIT](LICENSE.md). Copyright (c) 2026 Jayson Vantuyl.
