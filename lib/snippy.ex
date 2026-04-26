defmodule Snippy do
  @moduledoc """
  Discover SSL certificates and keys from environment variables and produce
  configuration suitable for `:ssl`, Cowboy, Ranch, Bandit, Thousand Island,
  or Phoenix.

  ## How it works

  Snippy runs in three lazy phases backed by a single shared `GenServer`:

    1. **Scan** (cheap). The Store walks the environment once and records
       every variable whose name ends in a recognized suffix (`_CRT`,
       `_KEY`, `_PWD`, ...). No PEM is decoded, no files are read. The scan
       is shared across every helper call.

    2. **Filter by prefix** (per call). Each helper takes the broad scan
       results and peels off entries whose names start with the requested
       prefix.

    3. **Materialize** (lazy, per group). Only when a helper actually asks
       about a `(prefix, key)` group does Snippy decode PEM, decrypt keys,
       validate the cert/key match, check expiry, and build the final
       `:ssl` payload. Successes *and* errors are memoized in ETS, so
       repeated lookups are constant-time and broken groups don't spam the
       log.

  This shape gives Snippy a small DoS surface: env vars that no helper ever
  asks about never get decoded, even if an attacker can set arbitrary
  environment variables.

  ## Helper option groups

  All helpers accept the same option categories:

    * **Required**
      - `:prefix` - string, atom, or list of either.

    * **Discovery passthrough** (forwarded to the shared scan)
      - `:case_sensitive` - default `true`.
      - `:env` - env map override (mainly for testing).
      - `:reload_interval_ms` - if set, the Store schedules background
        re-scans at this cadence.

    * **Per-lookup options**
      - `:default_hostname` - SNI fallback host.
      - `:expiry_grace_seconds` - tolerate certs that expired up to this
        many seconds ago (default 0).
      - `:public_ca_validation` - `:auto | :always | :never` (default
        `:auto`).
      - `:only` - list of hostname patterns; only matching groups are
        exposed.
      - `:keys` - list of group key strings (or atoms); only matching
        groups are exposed.

    * **Escape hatch**
      - `:discovered_certs` - a `%Snippy.Discovery{}` from a prior call to
        `discover_certificates/1`. When provided, the helper uses *that*
        discovery's groups directly and skips the shared Store entirely.
        Useful when you want to control exactly when (and against what
        env) materialization happens, e.g. pre-warming at boot.

  ## Quick example

      Snippy.cowboy_opts(prefix: "MYAPP")

      # equivalent to:
      {:ok, disc} = Snippy.discover_certificates(prefix: "MYAPP")
      Snippy.cowboy_opts(prefix: "MYAPP", discovered_certs: disc)
  """

  alias Snippy.Discovery
  alias Snippy.Lookup
  alias Snippy.Store

  @type discovery :: %Discovery{}

  # ----------------------------------------------------- Discovery handles

  @doc """
  Run discovery against the env and return a `%Snippy.Discovery{}` handle.

  Eagerly materializes every group that matches `:prefix`, so this is a
  good pre-warm step at boot. The returned handle's `:groups` field
  contains the successful groups (without their internal `:ssl` payloads —
  those live in the Store's ETS); `:errors` contains any per-group
  materialization failures as `{prefix, key, reason}` tuples.

  Options: see the moduledoc.
  """
  @spec discover_certificates(keyword()) :: {:ok, discovery()} | no_return
  def discover_certificates(opts \\ []) do
    Snippy.OTPCheck.check!()
    Store.discover(opts)
  end

  @doc """
  Re-scan the env (and re-read all `_FILE` sources). Clears the
  materialization cache so subsequent helper calls re-decode.

  Returns a refreshed `%Snippy.Discovery{}` for the same prefix(es) the
  handle was created with.
  """
  @spec reload(discovery()) :: {:ok, discovery()} | {:error, term()}
  def reload(%Discovery{} = disc) do
    case Store.reload([]) do
      :ok ->
        # Re-run discovery for the original handle's prefix scope.
        opts =
          [default_hostname: disc.default_hostname, reload_interval_ms: disc.reload_interval_ms]
          |> Keyword.put(:prefix, prefixes_from_handle(disc))

        Store.discover(opts)

      {:error, _} = err ->
        err
    end
  end

  defp prefixes_from_handle(%Discovery{groups: groups}) do
    groups |> Enum.map(& &1.prefix) |> Enum.uniq()
  end

  # ----------------------------------------------------------- Helpers ---

  @doc """
  Build an SNI fun (suitable for the `:sni_fun` :ssl option).
  """
  @spec sni(keyword()) :: (binary() | charlist() -> keyword())
  def sni(opts \\ []) do
    groups = resolve_groups(opts)
    Lookup.sni_fun(groups, lookup_opts(opts))
  end

  @doc """
  Build a keyword list of `:ssl.listen/2` options.
  """
  @spec ssl_opts(keyword()) :: keyword()
  def ssl_opts(opts \\ []) do
    groups = resolve_groups(opts)
    Lookup.ssl_opts(groups, lookup_opts(opts))
  end

  @doc """
  Build options suitable for `Plug.Cowboy.https/3` / `:cowboy.start_tls/3`.
  """
  @spec cowboy_opts(keyword()) :: keyword()
  def cowboy_opts(opts \\ []) do
    ssl_opts(opts)
  end

  @doc """
  Build options suitable for Ranch's `:ranch.start_listener/5`.
  """
  @spec ranch_opts(keyword()) :: keyword()
  def ranch_opts(opts \\ []) do
    [socket_opts: ssl_opts(opts)]
  end

  @doc """
  Build options suitable for `Bandit.start_link/1`.
  """
  @spec bandit_opts(keyword()) :: keyword()
  def bandit_opts(opts \\ []) do
    [thousand_island_options: thousand_island_opts(opts)]
  end

  @doc """
  Build options suitable for `ThousandIsland.start_link/1`.
  """
  @spec thousand_island_opts(keyword()) :: keyword()
  def thousand_island_opts(opts \\ []) do
    [transport_options: ssl_opts(opts)]
  end

  @doc """
  Build the keyword list to assign to the `:https` key of a Phoenix
  endpoint config.

  Accepts both Phoenix transport opts (e.g. `:port`, `:cipher_suite`,
  `:otp_app`) and Snippy scoping opts (`:only`, `:keys`). Snippy's SSL
  options (`:sni_fun`, `:certs_keys`) are merged in last so they win on
  collision; everything else is passed through unchanged.

  Discovery passthrough opts (`:prefix`, `:case_sensitive`, ...) are
  consumed for discovery and stripped from the result.

  ## Example

      # config/runtime.exs
      config :my_app, MyAppWeb.Endpoint,
        https:
          Snippy.phx_endpoint_config(
            prefix: "MYAPP",
            port: 4443,
            cipher_suite: :strong
          )
  """
  @spec phx_endpoint_config(keyword()) :: keyword()
  def phx_endpoint_config(opts \\ []) do
    {snippy_opts, transport_opts} = split_snippy_opts(opts)
    Keyword.merge(transport_opts, ssl_opts(snippy_opts))
  end

  # --------------------------------------------------------- Internals ---

  @snippy_opt_keys [
    :prefix,
    :case_sensitive,
    :env,
    :reload_interval_ms,
    :default_hostname,
    :expiry_grace_seconds,
    :public_ca_validation,
    :only,
    :keys,
    :discovered_certs
  ]

  defp split_snippy_opts(opts) do
    Keyword.split(opts, @snippy_opt_keys)
  end

  defp resolve_groups(opts) do
    cond do
      Keyword.has_key?(opts, :discovered_certs) ->
        %Discovery{groups: groups} = Keyword.fetch!(opts, :discovered_certs)
        Lookup.hydrate_groups(groups)

      Keyword.has_key?(opts, :env) ->
        # Isolated discovery: bypass the shared Store entirely. Useful in
        # tests and any caller that wants to pin discovery to a specific
        # env without touching shared state.
        {:ok, %Discovery{groups: groups}} = Store.discover(opts)
        Lookup.hydrate_groups(groups)

      true ->
        prefixes = Discovery.normalize_prefixes!(opts[:prefix])
        Store.lookup_groups(prefixes, scan_and_lookup_opts(opts))
    end
  end

  defp scan_and_lookup_opts(opts) do
    Keyword.take(opts, [
      :case_sensitive,
      :env,
      :reload_interval_ms,
      :expiry_grace_seconds,
      :public_ca_validation
    ])
  end

  defp lookup_opts(opts) do
    Keyword.take(opts, [:only, :keys, :default_hostname])
  end
end
