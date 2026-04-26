# Changelog

## 0.6.0 (breaking)

### Breaking changes

All seven helper functions have been changed from `(discovery, opts)` to
opts-only. Pass `:prefix` directly:

```elixir
# 0.5.x
{:ok, disc} = Snippy.discover_certificates(prefix: "MYAPP")
Snippy.cowboy_opts(disc, port: 4443)

# 0.6.0
Snippy.cowboy_opts(prefix: "MYAPP", port: 4443)
```

The `discovered_certs` option lets advanced callers thread a pre-built
`%Snippy.Discovery{}` through, recovering the old behavior and giving
control over when materialization happens:

```elixir
{:ok, disc} = Snippy.discover_certificates(prefix: "MYAPP")
Snippy.cowboy_opts(prefix: "MYAPP", discovered_certs: disc, port: 4443)
```

### What changed under the hood

- A single shared `Snippy.Store` `GenServer` now owns the env scan. The
  scan happens once on first use and is shared across every helper call,
  every prefix.
- The scan no longer pre-filters by prefix. Helpers filter the in-memory
  scan list by prefix on every call, so adding new prefixes to a running
  system doesn't require a rescan.
- PEM decoding, key decryption, validity checks, and chain validation
  happen lazily on first lookup of a `(prefix, key)` group. Both
  successes and failures are memoized in ETS.
  - Env vars whose `(prefix, key)` no helper ever asks about are never
    decoded, even if they look like Snippy vars.
  - This narrows the DoS surface against attackers who can set arbitrary
    env vars but don't control the running config.
- The shared scan runs under a `Task.Supervisor` so a scan crash doesn't
  take the Store down.
- `%Snippy.Discovery{}` gained an `:errors` field listing per-group
  materialization failures as `{prefix, key, reason}` tuples.
- Dropped `:memoize` dependency; replaced with explicit ETS memoization.

### Mix task

`mix snippy.test` now reports per-group materialization errors and
prints a scope-survival summary when `--only`/`--key` is given. New
`--quiet` flag suppresses per-group output.

### Migration

Replace each call site:

| Before | After |
| --- | --- |
| `Snippy.sni(disc, opts)` | `Snippy.sni([prefix: ..., \| opts])` |
| `Snippy.ssl_opts(disc, opts)` | `Snippy.ssl_opts([prefix: ..., \| opts])` |
| `Snippy.cowboy_opts(disc, opts)` | `Snippy.cowboy_opts([prefix: ..., \| opts])` |
| `Snippy.ranch_opts(disc, opts)` | `Snippy.ranch_opts([prefix: ..., \| opts])` |
| `Snippy.bandit_opts(disc, opts)` | `Snippy.bandit_opts([prefix: ..., \| opts])` |
| `Snippy.thousand_island_opts(disc, opts)` | `Snippy.thousand_island_opts([prefix: ..., \| opts])` |
| `Snippy.phx_endpoint_config(disc, opts)` | `Snippy.phx_endpoint_config([prefix: ..., \| opts])` |

If you want to keep using a pre-built handle, append
`discovered_certs: disc` to each call.

## 0.5.0

Initial public release.
