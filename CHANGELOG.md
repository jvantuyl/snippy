# Changelog

## 0.10.1

### Internals

- Closed the last gaps in line coverage. The four previously-uncovered
  defensive branches (`Discovery.check_validity/3`'s `ArgumentError`
  rescue, `Store.__test_reset__/0`'s rescue when the ETS table is gone,
  `Store.current_scan/0`'s `:undefined` branch, and
  `OTPCheck.check!/0`'s runtime raise) are now exercised by
  `rewire`-driven unit tests.
- New `Snippy.OtpInfo` helper module wraps
  `:erlang.system_info(:otp_release)` so `OTPCheck` can be rewired
  without monkey-patching the Erlang `:erlang` module.
- `Snippy.Store` no longer carries a `safe_delete/2` helper; the
  `__test_reset__` body now wraps all of its `:ets.*` calls in a single
  `try/rescue` that treats a missing table as a successful reset (which
  is the desired end state).
- 236 tests + 9 properties, 100.0% line coverage.

## 0.10.0

### New features

- **Discovery logging.** Config-building helpers (`ssl_opts/1`,
  `cowboy_opts/1`, `bandit_opts/1`, `phx_endpoint_config/1`, etc.)
  now emit debug-level log messages describing discovered certificate
  groups, including hostnames, key type, validity dates, fingerprints,
  and chain validation status. Prefix(es) are included in the
  announcement line.

- **`:log_level` option.** Pass `log_level: :info` (or any Logger
  level) to control the level of discovery log messages. Pass
  `log_level: false` or `log_level: :none` to suppress logging
  entirely. The default can also be set via
  `config :snippy, log_level: :debug`.

- **Change suppression.** Repeated calls with the same certificate
  set produce no duplicate log output. After a `Store.reload/1`,
  logging is suppressed if the certificates are unchanged; only
  actual changes trigger re-emission.

## 0.9.0

### Fixes

- **Helpers now work from `config/runtime.exs` before the Snippy
  application starts.** Previously, calling `Snippy.phx_endpoint_config/1`,
  `Snippy.ssl_opts/1`, or any other helper before the supervision tree
  was running would crash with an `ArgumentError` on the missing
  `:snippy_certs` ETS table. Snippy now detects when its infrastructure
  is unavailable and transparently falls back to in-process discovery
  (scan + materialize without GenServer or ETS). No code changes
  required on the caller side.

### New features

- **`phx_endpoint_config/1` supports Bandit via `:adapter` option.**
  Pass `adapter: :bandit` to nest SSL options under
  `thousand_island_options: [transport_options: [...]]` as Bandit
  requires. Defaults to `:cowboy` (flat merge, existing behavior).

### Internals

- `Snippy.Store.lookup_groups/2` and `Snippy.Store.discover/1` route
  through a local fallback path when the ETS table has not been created
  yet, reusing the existing `Discovery.scan_all/1` and
  `Discovery.materialize_group/2` pipeline.
- `Snippy.Store.current_scan/0` guards against a missing ETS table via
  `:ets.whereis/1`.
- Removed a defensive `{:error, :materialize_missing}` branch in
  `fetch_or_materialize/2`; a missing row after a GenServer materialize
  call now crashes immediately (let-it-crash).
- `Snippy.TableOwner` gained test-only `__test_hide_table__/0` and
  `__test_restore_table__/0` helpers for simulating a missing table
  without stopping the application.
- 213 tests + 9 properties, 99.6% line coverage.

## 0.8.3

First release published to Hex.

Documentation-only fix: configure `ex_doc` to skip undefined-reference
warnings on `CHANGELOG.md` so its narrative mentions of internal
`@moduledoc false` modules (e.g. `Snippy.Store`) don't trigger build
warnings. No code changes.

## 0.8.2 (unreleased)

### Breaking changes

- **OCSP stapling support removed.** The `:ocsp_stapling?` group flag,
  the `_OCSP_STAPLING` (and `_OSCP_STAPLING` typo-alias) suffixes, and
  the related extraction/parsing helpers are gone. OTP's `:ssl` does
  not perform server-side OCSP stapling, so the previous configuration
  knobs were inert. Strip any `_OCSP_STAPLING` env vars and any
  references to `:ocsp_stapling?` from your code.

### New env-var aliases

- `_CERT` and `_CERT_FILE` are now recognized alongside `_CRT` /
  `_CRT_FILE`. `_CACERT` / `_CACERT_FILE` are recognized alongside
  `_CACRT` / `_CACRT_FILE`. The two spellings are interchangeable for a
  given group.

### Fixes & internals

- Added an `:errors` field on `%Snippy.Discovery{}` listing per-group
  materialization failures as `{prefix, key, reason}` tuples (carried
  over from the 0.6.0 series and now stable).
- Hardened the shared `Snippy.Store`: scan crashes and timeouts surface
  as structured errors rather than killing the GenServer; scheduled
  reload failures are logged but do not stop the timer.
- Improved `mix snippy.test` reporting and added a `--quiet` flag.
- Test suite cleanup: 208 tests + 9 properties, 99.6% line coverage,
  `mix credo --strict` clean, and a new `mix lint` alias chained into
  `mix ci`.

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
