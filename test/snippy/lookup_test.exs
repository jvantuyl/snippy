defmodule Snippy.LookupTest do
  @moduledoc """
  Direct tests for `Snippy.Lookup`'s SNI fun, scoping, fallback, and
  hydration logic. These exercise branches not reachable from the
  isolated-discovery `:env` fast path used by most helper tests.
  """

  use ExUnit.Case, async: false

  alias Snippy.Lookup
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    Snippy.Store.__test_reset__()

    on_exit(fn ->
      cleanup_env()
      Snippy.Store.__test_reset__()
      TestFixtures.cleanup(fx)
    end)

    %{fx: fx}
  end

  describe "hydrate_groups/1 — shared-Store hydration path" do
    test "fills payloads from the live Store when groups arrive stripped", %{fx: fx} do
      System.put_env("LKA_M_CRT", fx.pem.a_cert)
      System.put_env("LKA_M_KEY", fx.pem.a_key)

      {:ok, disc} = Snippy.discover_certificates(prefix: "LKA")
      [g] = disc.groups

      # Public handle from a shared discovery has its payload stripped.
      assert g.ssl_payload == nil

      [hydrated] = Lookup.hydrate_groups([g])

      assert is_map(hydrated.ssl_payload)
      assert hydrated.prefix == "LKA"
      assert hydrated.key == "M"
    end

    test "drops groups whose materialized form is missing in the Store", %{fx: fx} do
      _ = fx

      stranded = %Snippy.Discovery.Group{
        prefix: "PREFIX_THAT_NEVER_MATERIALIZED",
        key: "K",
        hostnames: ["nope.example"],
        ssl_payload: nil
      }

      assert Lookup.hydrate_groups([stranded]) == []
    end

    test "passes through groups that already carry a payload", %{fx: fx} do
      env = %{
        "ISO_M_CRT" => fx.pem.a_cert,
        "ISO_M_KEY" => fx.pem.a_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "ISO", env: env)
      [g] = disc.groups
      assert is_map(g.ssl_payload)

      assert [^g] = Lookup.hydrate_groups([g])
    end
  end

  describe "sni_fun scope — :only" do
    test ":only that excludes every group falls back to the first available", %{fx: fx} do
      # Hits the `[] -> [hd(groups)]` branch in fallback_entries/2 (no
      # default_hostname, scope filters everything out, and we still need
      # *some* fallback so :ssl can finish the handshake).
      env = %{
        "STG_A_CRT" => fx.pem.a_cert,
        "STG_A_KEY" => fx.pem.a_key
      }

      ssl =
        Snippy.ssl_opts(
          prefix: "STG",
          env: env,
          only: ["nothing-matches.example"]
        )

      assert [_one] = ssl[:certs_keys]
    end

    test ":only with a non-matching pattern still falls back via scoped fallback", %{fx: fx} do
      env = %{
        "STG_A_CRT" => fx.pem.a_cert,
        "STG_A_KEY" => fx.pem.a_key,
        "STG_B_CRT" => fx.pem.b_cert,
        "STG_B_KEY" => fx.pem.b_key
      }

      sni_fun =
        Snippy.sni(prefix: "STG", env: env, only: ["a.example.com"])

      assert [certs_keys: certs] = sni_fun.("a.example.com")
      assert length(certs) == 1

      # nonexistent host: falls back to the scoped fallback (which is
      # built only from groups that pass :only — i.e. just A).
      assert [certs_keys: fb] = sni_fun.("nowhere.example.test")
      assert length(fb) == 1
    end

    test "wildcard pattern in :only matches normalized host names", %{fx: fx} do
      env = %{
        "STG_W_CRT" => fx.pem.wild_cert,
        "STG_W_KEY" => fx.pem.wild_key
      }

      sni_fun =
        Snippy.sni(prefix: "STG", env: env, only: ["*.wild.example.com"])

      assert [certs_keys: certs] = sni_fun.("anything.wild.example.com")
      assert length(certs) == 1
    end
  end

  describe "sni_fun scope — :keys" do
    test "string :keys filters groups by uppercase key", %{fx: fx} do
      env = %{
        "STG_A_CRT" => fx.pem.a_cert,
        "STG_A_KEY" => fx.pem.a_key,
        "STG_B_CRT" => fx.pem.b_cert,
        "STG_B_KEY" => fx.pem.b_key
      }

      ssl = Snippy.ssl_opts(prefix: "STG", env: env, keys: ["A"])
      assert [_] = ssl[:certs_keys]
    end

    test "atom :keys are normalized to upcased strings and used", %{fx: fx} do
      env = %{
        "STG_A_CRT" => fx.pem.a_cert,
        "STG_A_KEY" => fx.pem.a_key,
        "STG_B_CRT" => fx.pem.b_cert,
        "STG_B_KEY" => fx.pem.b_key
      }

      ssl = Snippy.ssl_opts(prefix: "STG", env: env, keys: [:b])
      assert [_] = ssl[:certs_keys]
    end
  end

  describe "default_hostname fallback" do
    test "default_hostname not under any cert produces an empty fallback", %{fx: fx} do
      # Hits the `true -> []` branch in fallback_entries/2 (default_hostname
      # set but no group serves it; no :only scope to log a warning about).
      env = %{
        "STG_A_CRT" => fx.pem.a_cert,
        "STG_A_KEY" => fx.pem.a_key
      }

      ssl =
        Snippy.ssl_opts(
          prefix: "STG",
          env: env,
          default_hostname: "totally-unrelated.test"
        )

      assert ssl[:certs_keys] == []
      # And the SNI fun for an unrelated host returns []
      assert ssl[:sni_fun].("nope.example.test") == []
    end

    test "default_hostname matches a wildcard cert", %{fx: fx} do
      env = %{
        "STG_W_CRT" => fx.pem.wild_cert,
        "STG_W_KEY" => fx.pem.wild_key
      }

      ssl =
        Snippy.ssl_opts(
          prefix: "STG",
          env: env,
          default_hostname: "anything.wild.example.com"
        )

      assert [_] = ssl[:certs_keys]
    end
  end

  describe "no-cert / empty-Discovery case" do
    test "ssl_opts with no groups yields empty :certs_keys" do
      env = %{}

      ssl = Snippy.ssl_opts(prefix: "MISS", env: env)

      assert ssl[:certs_keys] == []
      assert is_function(ssl[:sni_fun], 1)

      # SNI fun with no groups returns []
      assert ssl[:sni_fun].("anything") == []
    end
  end

  defp cleanup_env do
    Enum.each(
      ~w(LKA_M_CRT LKA_M_KEY STG_A_CRT STG_A_KEY STG_B_CRT STG_B_KEY STG_W_CRT STG_W_KEY),
      &System.delete_env/1
    )
  end
end
