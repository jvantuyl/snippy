defmodule Snippy.AdaptersTest do
  @moduledoc """
  Integration tests that prove `Snippy.cowboy_opts/1`, `Snippy.bandit_opts/1`,
  `Snippy.ranch_opts/1`, and `Snippy.thousand_island_opts/1` produce keyword
  lists that the corresponding adapters actually accept.

  Each test:
    * starts an HTTPS listener using the adapter's normal start function,
    * connects with two SNI hostnames,
    * asserts both handshakes succeed and the right cert is presented.

  These are slower than the pure-logic tests but catch shape mistakes
  (`:transport_options` vs `:thousand_island_options`, etc.) that unit
  tests can't see.
  """

  use ExUnit.Case, async: false

  alias Snippy.Decoder
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)

    env = %{
      "ADP_A_CRT" => fx.pem.a_cert,
      "ADP_A_KEY" => fx.pem.a_key,
      "ADP_B_CRT" => fx.pem.b_cert,
      "ADP_B_KEY" => fx.pem.b_key
    }

    {:ok, disc} = Snippy.discover_certificates(prefix: "ADP", env: env)
    %{fx: fx, disc: disc}
  end

  describe "Plug.Cowboy" do
    test "https adapter accepts cowboy_opts and serves correct cert per SNI",
         %{disc: disc} do
      cowboy_opts = Snippy.cowboy_opts(prefix: "ADP", discovered_certs: disc)

      {:ok, _pid} =
        Plug.Cowboy.https(
          EmptyPlug,
          [],
          [port: 0, ref: :snippy_cowboy_test] ++ cowboy_opts
        )

      port = :ranch.get_port(:snippy_cowboy_test)

      try do
        assert "a.example.com" == leaf_cn_for_sni(port, "a.example.com")
        assert "b.example.com" == leaf_cn_for_sni(port, "b.example.com")
      after
        :ok = Plug.Cowboy.shutdown(:snippy_cowboy_test)
      end
    end
  end

  describe "Bandit" do
    test "start_link accepts bandit_opts and serves correct cert per SNI",
         %{disc: disc} do
      bandit_opts = Snippy.bandit_opts(prefix: "ADP", discovered_certs: disc)

      {:ok, pid} =
        Bandit.start_link([plug: EmptyPlug, scheme: :https, port: 0] ++ bandit_opts)

      port = bandit_port(pid)

      try do
        assert "a.example.com" == leaf_cn_for_sni(port, "a.example.com")
        assert "b.example.com" == leaf_cn_for_sni(port, "b.example.com")
      after
        Process.exit(pid, :normal)
      end
    end
  end

  describe "Ranch" do
    test "start_listener accepts ranch_opts and serves correct cert per SNI",
         %{disc: disc} do
      ranch_opts = Snippy.ranch_opts(prefix: "ADP", discovered_certs: disc)

      transport_opts = %{
        socket_opts: [{:port, 0} | Keyword.get(ranch_opts, :socket_opts)]
      }

      {:ok, _pid} =
        :ranch.start_listener(
          :snippy_ranch_test,
          :ranch_ssl,
          transport_opts,
          EchoProtocol,
          []
        )

      port = :ranch.get_port(:snippy_ranch_test)

      try do
        assert "a.example.com" == leaf_cn_for_sni(port, "a.example.com")
        assert "b.example.com" == leaf_cn_for_sni(port, "b.example.com")
      after
        :ranch.stop_listener(:snippy_ranch_test)
      end
    end
  end

  describe "ThousandIsland" do
    test "start_link accepts thousand_island_opts and serves correct cert per SNI",
         %{disc: disc} do
      ti_opts = Snippy.thousand_island_opts(prefix: "ADP", discovered_certs: disc)

      transport_options =
        Keyword.get(ti_opts, :transport_options, [])
        |> Keyword.put(:port, 0)

      {:ok, pid} =
        ThousandIsland.start_link(
          handler_module: EchoHandler,
          transport_module: ThousandIsland.Transports.SSL,
          transport_options: transport_options,
          port: 0
        )

      {:ok, port} = ThousandIsland.listener_info(pid)

      port =
        case port do
          {_addr, p} -> p
          p when is_integer(p) -> p
        end

      try do
        assert "a.example.com" == leaf_cn_for_sni(port, "a.example.com")
        assert "b.example.com" == leaf_cn_for_sni(port, "b.example.com")
      after
        ThousandIsland.stop(pid)
      end
    end
  end

  # ---------- shared client ----------

  defp leaf_cn_for_sni(port, sni_host) do
    {:ok, sock} =
      :ssl.connect(
        ~c"127.0.0.1",
        port,
        [
          active: false,
          verify: :verify_none,
          server_name_indication: String.to_charlist(sni_host)
        ],
        5_000
      )

    {:ok, peer_der} = :ssl.peercert(sock)
    :ssl.close(sock)

    case Decoder.cert_hostnames(peer_der) do
      [first | _] -> first
      [] -> nil
    end
  end

  defp bandit_port(pid) do
    # Bandit emits its bound port via ThousandIsland.listener_info on its
    # internal acceptor pid; we ask for the parent's runtime info instead.
    case ThousandIsland.listener_info(find_thousand_island_child(pid)) do
      {:ok, {_addr, port}} -> port
      {:ok, port} when is_integer(port) -> port
    end
  end

  defp find_thousand_island_child(supervisor_pid) do
    supervisor_pid
    |> Supervisor.which_children()
    |> Enum.find_value(fn
      {_id, child, _type, [ThousandIsland]} when is_pid(child) -> child
      {ThousandIsland, child, _type, _mods} when is_pid(child) -> child
      _ -> nil
    end) || supervisor_pid
  end
end

defmodule EmptyPlug do
  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    Plug.Conn.send_resp(conn, 200, "ok")
  end
end

defmodule EchoProtocol do
  # A trivial Ranch protocol: just complete the TLS handshake and accept;
  # the test only inspects the peer cert, not the application data.
  @behaviour :ranch_protocol

  @impl true
  def start_link(ref, transport, opts) do
    pid = spawn_link(fn -> init(ref, transport, opts) end)
    {:ok, pid}
  end

  defp init(ref, transport, _opts) do
    {:ok, socket} = :ranch.handshake(ref)
    transport.close(socket)
  end
end

defmodule EchoHandler do
  use ThousandIsland.Handler

  @impl ThousandIsland.Handler
  def handle_connection(_socket, state) do
    {:close, state}
  end
end
