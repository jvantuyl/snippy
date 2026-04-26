defmodule Snippy do
  @moduledoc """
  Discover SSL certificates and keys from environmental variables and produce
  configuration suitable for `:ssl`, Cowboy, Ranch, Bandit, or Thousand Island.
  """

  alias Snippy.Discovery
  alias Snippy.Store

  @type discovery :: %Discovery{}

  @doc """
  Run discovery and return a `%Snippy.Discovery{}` handle.

  Options:
    * `:prefix` (required) - string, atom, or list of either
    * `:case_sensitive` - default `true`
    * `:default_hostname` - default fallback host for non-SNI clients
    * `:reload_interval_ms` - if set, the store will periodically reload
    * `:expiry_grace_seconds` - default 0
    * `:public_ca_validation` - `:auto | :always | :never`, default `:auto`
    * `:env` - testing override map
  """
  @spec discover_certificates(keyword()) :: {:ok, discovery()} | no_return
  def discover_certificates(opts \\ []) do
    Snippy.OTPCheck.check!()
    Store.discover(opts)
  end

  @doc """
  Re-scan the env (and re-read all `_FILE` sources) for an existing discovery.
  """
  @spec reload(discovery()) :: {:ok, discovery()}
  def reload(%Discovery{} = disc) do
    Store.reload(disc)
  end

  @doc """
  Build an SNI fun (suitable for the `:sni_fun` :ssl option).
  """
  @spec sni(discovery(), keyword()) :: (binary() | charlist() -> keyword())
  def sni(%Discovery{} = disc, opts \\ []) do
    Snippy.Lookup.sni_fun(disc, opts)
  end

  @doc """
  Build a keyword list of `:ssl.listen/2` options.
  """
  @spec ssl_opts(discovery(), keyword()) :: keyword()
  def ssl_opts(%Discovery{} = disc, opts \\ []) do
    Snippy.Lookup.ssl_opts(disc, opts)
  end

  @doc """
  Build options suitable for `Plug.Cowboy.https/3` / `:cowboy.start_tls/3`.
  """
  @spec cowboy_opts(discovery(), keyword()) :: keyword()
  def cowboy_opts(%Discovery{} = disc, opts \\ []) do
    ssl_opts(disc, opts)
  end

  @doc """
  Build options suitable for Ranch's `:ranch.start_listener/5`.
  """
  @spec ranch_opts(discovery(), keyword()) :: keyword()
  def ranch_opts(%Discovery{} = disc, opts \\ []) do
    [socket_opts: ssl_opts(disc, opts)]
  end

  @doc """
  Build options suitable for `Bandit.start_link/1`.
  """
  @spec bandit_opts(discovery(), keyword()) :: keyword()
  def bandit_opts(%Discovery{} = disc, opts \\ []) do
    [thousand_island_options: thousand_island_opts(disc, opts)]
  end

  @doc """
  Build options suitable for `ThousandIsland.start_link/1`.
  """
  @spec thousand_island_opts(discovery(), keyword()) :: keyword()
  def thousand_island_opts(%Discovery{} = disc, opts \\ []) do
    [transport_options: ssl_opts(disc, opts)]
  end

  @doc """
  Build the keyword list to assign to the `:https` key of a Phoenix
  endpoint config.

  Accepts both Phoenix transport opts (e.g. `:port`, `:cipher_suite`,
  `:otp_app`) and Snippy scoping opts (`:only`, `:keys`). Snippy's SSL
  options (`:sni_fun`, `:certs_keys`) are merged in last so they win on
  collision; everything else is passed through unchanged.

  ## Example

      # config/runtime.exs
      {:ok, disc} = Snippy.discover_certificates(prefix: "MYAPP")

      config :my_app, MyAppWeb.Endpoint,
        https: Snippy.endpoint_https(disc, port: 4443, cipher_suite: :strong)
  """
  @spec endpoint_https(discovery(), keyword()) :: keyword()
  def endpoint_https(%Discovery{} = disc, opts \\ []) do
    {scope_opts, transport_opts} = Keyword.split(opts, [:only, :keys])
    Keyword.merge(transport_opts, ssl_opts(disc, scope_opts))
  end
end
