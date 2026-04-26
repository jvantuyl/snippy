defmodule SnippySniIntegrationTest do
  @moduledoc """
  Stands up a real `:ssl` listener configured by `Snippy.ssl_opts/1`,
  connects to it with several different SNI hostnames, and verifies the
  server presented the expected leaf certificate for each. This is the
  end-to-end check that `:sni_fun` is wired up and that wildcard /
  fallback selection actually works inside OTP's TLS handshake.
  """

  use ExUnit.Case, async: false

  alias Snippy.Decoder
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  test "SNI selects a.example.com, b.example.com, wildcard, and falls back",
       %{fx: fx} do
    env = %{
      "APP_A_CRT" => fx.pem.a_cert,
      "APP_A_KEY" => fx.pem.a_key,
      "APP_B_CRT" => fx.pem.b_cert,
      "APP_B_KEY" => fx.pem.b_key,
      "APP_WILD_CRT" => fx.pem.wild_cert,
      "APP_WILD_KEY" => fx.pem.wild_key
    }

    ssl_opts = Snippy.ssl_opts(prefix: "APP", env: env, default_hostname: "a.example.com")

    listen_opts =
      ssl_opts
      |> Keyword.merge(
        active: false,
        reuseaddr: true,
        verify: :verify_none
      )

    {:ok, listen_socket} = :ssl.listen(0, listen_opts)
    {:ok, {_addr, port}} = :ssl.sockname(listen_socket)

    parent = self()

    server_loop = fn loop ->
      case :ssl.transport_accept(listen_socket) do
        {:ok, transport} ->
          case :ssl.handshake(transport, 5_000) do
            {:ok, _socket} ->
              :ok

            {:error, reason} ->
              send(parent, {:server_error, reason})
          end

          loop.(loop)

        {:error, :closed} ->
          :ok
      end
    end

    server = spawn_link(fn -> server_loop.(server_loop) end)

    on_exit(fn ->
      :ssl.close(listen_socket)
      Process.exit(server, :kill)
    end)

    # ----- 1. exact match for "a.example.com" -----
    assert "a.example.com" == leaf_cn_for_sni(port, "a.example.com")

    # ----- 2. exact match for "b.example.com" -----
    assert "b.example.com" == leaf_cn_for_sni(port, "b.example.com")

    # ----- 3. wildcard match for "*.wild.example.com" -----
    # The wildcard cert advertises SAN=*.wild.example.com; SNI for any
    # immediate child label should pick it.
    assert "*.wild.example.com" == leaf_cn_for_sni(port, "host.wild.example.com")

    # ----- 4. unknown SNI falls back to default_hostname (a.example.com) -----
    assert "a.example.com" == leaf_cn_for_sni(port, "no-such-host.example.org")
  end

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

    cn_from_cert(peer_der)
  end

  defp cn_from_cert(der) do
    # `Snippy.Decoder.cert_hostnames/1` returns SAN dNS + CN; for our test
    # fixtures the CN is the hostname we're checking against.
    case Decoder.cert_hostnames(der) do
      [first | _] -> first
      [] -> nil
    end
  end
end
