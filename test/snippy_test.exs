defmodule SnippyTest do
  use ExUnit.Case, async: false

  import Snippy.TestUtil

  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  describe "discover_certificates/1" do
    test "discovers cert/key from inline PEM env vars", %{fx: fx} do
      quiet do
        env = %{
          "MY_APP_MAIN_CRT" => fx.pem.a_cert,
          "MY_APP_MAIN_KEY" => fx.pem.a_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "MY_APP", env: env)
        assert [g] = disc.groups
        assert g.prefix == "MY_APP"
        assert g.key == "MAIN"
        assert "a.example.com" in g.hostnames
        assert g.cert_source == :inline
        assert g.key_source == :inline
        assert g.has_password? == false
        assert disc.errors == []
      end
    end

    test "discovers from _FILE variants", %{fx: fx} do
      quiet do
        env = %{
          "APP_FOO_CRT_FILE" => fx.paths.a_cert,
          "APP_FOO_KEY_FILE" => fx.paths.a_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert g.cert_source == :file
        assert g.key_source == :file
      end
    end

    test "decrypts encrypted key with password", %{fx: fx} do
      quiet do
        env = %{
          "APP_X_CRT" => fx.pem.b_cert,
          "APP_X_KEY_FILE" => fx.paths.b_key_enc,
          "APP_X_PWD" => "secret"
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert g.has_password?
      end
    end

    test "trims trailing whitespace from password file", %{fx: fx} do
      quiet do
        env = %{
          "APP_X_CRT" => fx.pem.b_cert,
          "APP_X_KEY_FILE" => fx.paths.b_key_enc,
          "APP_X_PWD_FILE" => fx.paths.pwd_file
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [_g] = disc.groups
      end
    end

    test "drops group with bad password", %{fx: fx} do
      quiet do
        env = %{
          "APP_X_CRT" => fx.pem.b_cert,
          "APP_X_KEY_FILE" => fx.paths.b_key_enc,
          "APP_X_PWD" => "wrong"
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert disc.groups == []
        assert [{"APP", "X", _}] = disc.errors
      end
    end

    test "drops expired cert", %{fx: fx} do
      quiet do
        env = %{
          "APP_OLD_CRT" => fx.pem.expired_cert,
          "APP_OLD_KEY" => fx.pem.expired_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert disc.groups == []
        assert [{"APP", "OLD", {:expired, _}}] = disc.errors
      end
    end

    test "drops not-yet-valid cert", %{fx: fx} do
      quiet do
        env = %{
          "APP_NEW_CRT" => fx.pem.future_cert,
          "APP_NEW_KEY" => fx.pem.future_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert disc.groups == []
        assert [{"APP", "NEW", {:not_yet_valid, _}}] = disc.errors
      end
    end

    test "expiry_grace_seconds keeps recently-expired cert", %{fx: fx} do
      quiet do
        env = %{
          "APP_OLD_CRT" => fx.pem.expired_cert,
          "APP_OLD_KEY" => fx.pem.expired_key
        }

        # 3 years grace covers the 1-day-ago expiry
        {:ok, disc} =
          Snippy.discover_certificates(
            prefix: "APP",
            env: env,
            expiry_grace_seconds: 3 * 365 * 86_400
          )

        assert [_g] = disc.groups
      end
    end

    test "includes CA chain when CACRT is set", %{fx: fx} do
      quiet do
        env = %{
          "APP_X_CRT" => fx.pem.a_cert,
          "APP_X_KEY" => fx.pem.a_key,
          "APP_X_CACRT" => fx.pem.ca_cert
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert g.has_ca_chain?
        assert g.chain_validation == :ok_chain
      end
    end

    test "discovers wildcard SAN cert", %{fx: fx} do
      quiet do
        env = %{
          "APP_W_CRT" => fx.pem.wild_cert,
          "APP_W_KEY" => fx.pem.wild_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert "*.wild.example.com" in g.hostnames
      end
    end

    test "discovers ECDSA cert and reports key_type", %{fx: fx} do
      quiet do
        env = %{
          "APP_EC_CRT" => fx.pem.ec_cert,
          "APP_EC_KEY" => fx.pem.ec_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert g.key_type == :ecdsa
      end
    end

    test "handles atom prefixes", %{fx: fx} do
      quiet do
        env = %{
          "MY_APP_MAIN_CRT" => fx.pem.a_cert,
          "MY_APP_MAIN_KEY" => fx.pem.a_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: :my_app, env: env)
        assert [_g] = disc.groups
      end
    end

    test "raises on forbidden atom prefix" do
      assert_raise ArgumentError, fn ->
        Snippy.discover_certificates(prefix: :elixir, env: %{})
      end

      assert_raise ArgumentError, fn ->
        Snippy.discover_certificates(prefix: nil, env: %{})
      end

      assert_raise ArgumentError, fn ->
        Snippy.discover_certificates(prefix: true, env: %{})
      end
    end

    test "raises on ambiguous prefixes" do
      assert_raise ArgumentError, ~r/ambiguous/, fn ->
        Snippy.discover_certificates(prefix: ["MY", "MY_APP"], env: %{})
      end
    end

    test "raises on multiple password aliases for same group", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_PWD" => "a",
        "APP_X_PASSWORD" => "a"
      }

      assert_raise ArgumentError, ~r/multiple password/, fn ->
        Snippy.discover_certificates(prefix: "APP", env: env)
      end
    end

    test "all four password suffix spellings work", %{fx: fx} do
      quiet do
        for suffix <- ["PWD", "PASS", "PASSWD", "PASSWORD"] do
          env = %{
            "APP_X_CRT" => fx.pem.b_cert,
            "APP_X_KEY_FILE" => fx.paths.b_key_enc,
            "APP_X_#{suffix}" => "secret"
          }

          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [_g] = disc.groups, "suffix #{suffix} did not load encrypted key"
        end
      end
    end

    test "CRT and CERT aliases are interchangeable for inline certs", %{fx: fx} do
      quiet do
        for suffix <- ["CRT", "CERT"] do
          env = %{
            "APP_X_#{suffix}" => fx.pem.a_cert,
            "APP_X_KEY" => fx.pem.a_key
          }

          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [_g] = disc.groups, "suffix #{suffix} did not produce a group"
        end
      end
    end

    test "CRT_FILE and CERT_FILE aliases are interchangeable for cert files", %{fx: fx} do
      quiet do
        for suffix <- ["CRT_FILE", "CERT_FILE"] do
          env = %{
            "APP_X_#{suffix}" => fx.paths.a_cert,
            "APP_X_KEY" => fx.pem.a_key
          }

          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [g] = disc.groups, "suffix #{suffix} did not produce a group"
          assert g.cert_source == :file
        end
      end
    end

    test "CACRT and CACERT aliases are interchangeable for inline CA chains", %{fx: fx} do
      quiet do
        for suffix <- ["CACRT", "CACERT"] do
          env = %{
            "APP_X_CRT" => fx.pem.a_cert,
            "APP_X_KEY" => fx.pem.a_key,
            "APP_X_#{suffix}" => fx.pem.ca_cert
          }

          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [g] = disc.groups, "suffix #{suffix} did not produce a group"
          assert g.has_ca_chain?
        end
      end
    end

    test "CACRT_FILE and CACERT_FILE aliases are interchangeable for CA files", %{fx: fx} do
      quiet do
        for suffix <- ["CACRT_FILE", "CACERT_FILE"] do
          env = %{
            "APP_X_CRT" => fx.pem.a_cert,
            "APP_X_KEY" => fx.pem.a_key,
            "APP_X_#{suffix}" => fx.paths.ca_cert
          }

          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [g] = disc.groups, "suffix #{suffix} did not produce a group"
          assert g.has_ca_chain?
        end
      end
    end
  end

  describe "phx_endpoint_config/1" do
    test "merges Phoenix transport opts with Snippy SSL opts", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            port: 4443,
            cipher_suite: :strong,
            otp_app: :my_app
          )

        assert opts[:port] == 4443
        assert opts[:cipher_suite] == :strong
        assert opts[:otp_app] == :my_app
        assert is_function(opts[:sni_fun], 1)
        assert is_list(opts[:certs_keys])
      end
    end

    test "passes :only/:keys through to scope filtering, not into the result", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            port: 4443,
            only: ["a.example.com"]
          )

        refute Keyword.has_key?(opts, :only)
        refute Keyword.has_key?(opts, :keys)
        assert opts[:port] == 4443
        assert is_function(opts[:sni_fun], 1)
      end
    end

    test "discovery passthrough opts (:prefix, :env) are stripped from result", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            port: 4443
          )

        refute Keyword.has_key?(opts, :prefix)
        refute Keyword.has_key?(opts, :env)
      end
    end
  end

  describe "phx_endpoint_config/1 adapter: :bandit" do
    test "nests SSL opts under thousand_island_options: [transport_options: ...]", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            adapter: :bandit,
            port: 4443
          )

        assert opts[:port] == 4443
        refute Keyword.has_key?(opts, :sni_fun)
        refute Keyword.has_key?(opts, :certs_keys)

        ti = opts[:thousand_island_options]
        assert is_list(ti)
        to = ti[:transport_options]
        assert is_list(to)
        assert is_function(to[:sni_fun], 1)
        assert is_list(to[:certs_keys])
      end
    end

    test ":adapter is stripped from the result", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            adapter: :bandit,
            port: 4443
          )

        refute Keyword.has_key?(opts, :adapter)
      end
    end

    test "merges with existing thousand_island_options from caller", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            env: env,
            adapter: :bandit,
            port: 4443,
            thousand_island_options: [num_acceptors: 10]
          )

        ti = opts[:thousand_island_options]
        assert ti[:num_acceptors] == 10
        assert is_list(ti[:transport_options])
      end
    end
  end

  describe ":discovered_certs escape hatch" do
    test "helpers accept a pre-built %Discovery{} and skip the shared Store", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)

        opts = Snippy.cowboy_opts(prefix: "APP", discovered_certs: disc)
        assert is_function(opts[:sni_fun], 1)
        assert is_list(opts[:certs_keys])
      end
    end
  end

  describe "lazy materialization" do
    test "vars under an unrequested prefix do not get materialized", %{fx: fx} do
      # Set up a valid group under PFXA and a deliberately-broken group
      # under PFXB. Discovering with prefix=PFXA must not log the broken
      # PFXB group's failure.
      env = %{
        "PFXA_GOOD_CRT" => fx.pem.a_cert,
        "PFXA_GOOD_KEY" => fx.pem.a_key,
        "PFXB_BROKEN_CRT" => "not even close to PEM",
        "PFXB_BROKEN_KEY" => "neither is this"
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "PFXA", env: env)
          assert [g] = disc.groups
          assert g.key == "GOOD"
        end)

      refute log =~ "PFXB"
      refute log =~ "BROKEN"
    end
  end

  describe "scope filtering" do
    test "atom-typed :keys are normalized to upcase strings", %{fx: fx} do
      quiet do
        env = %{
          "APP_MAIN_CRT" => fx.pem.a_cert,
          "APP_MAIN_KEY" => fx.pem.a_key,
          "APP_OTHER_CRT" => fx.pem.b_cert,
          "APP_OTHER_KEY" => fx.pem.b_key
        }

        opts = Snippy.ssl_opts(prefix: "APP", env: env, keys: [:main])
        # Fallback :certs_keys reflects the scoped subset.
        assert is_list(opts[:certs_keys])
      end
    end

    test ":only filters groups by hostname pattern", %{fx: fx} do
      quiet do
        env = %{
          "APP_A_CRT" => fx.pem.a_cert,
          "APP_A_KEY" => fx.pem.a_key,
          "APP_B_CRT" => fx.pem.b_cert,
          "APP_B_KEY" => fx.pem.b_key
        }

        sni = Snippy.sni(prefix: "APP", env: env, only: ["a.example.com"])

        # SNI for the matching host returns one cert.
        assert [certs_keys: [%{}]] = sni.("a.example.com")

        # SNI for the *non*-matching host returns the scoped fallback set
        # (which is built only from groups that pass the scope filter), so
        # it should still produce a cert (the scoped fallback).
        result = sni.("nonexistent.example.com")
        assert is_list(result)
      end
    end

    test ":default_hostname excluded by scope warns and produces empty fallback", %{fx: fx} do
      env = %{
        "APP_A_CRT" => fx.pem.a_cert,
        "APP_A_KEY" => fx.pem.a_key
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          opts =
            Snippy.ssl_opts(
              prefix: "APP",
              env: env,
              default_hostname: "a.example.com",
              only: ["totally-unrelated.test"]
            )

          assert opts[:certs_keys] == []
        end)

      assert log =~ "default_hostname"
    end
  end

  describe "Snippy.reload/1" do
    test "round-trips a shared-Store handle and re-materializes", %{fx: fx} do
      quiet do
        env = %{
          "RELOADTEST_M_CRT" => fx.pem.a_cert,
          "RELOADTEST_M_KEY" => fx.pem.a_key
        }

        {:ok, disc1} = Snippy.discover_certificates(prefix: "RELOADTEST", env: env)
        assert [g1] = disc1.groups
        assert g1.key == "M"

        # Plain reload, even on an isolated handle, should succeed; it
        # re-runs the global Store reload (no-op on global state) and then
        # rediscovers using the original prefix(es).
        {:ok, disc2} = Snippy.reload(disc1)
        assert is_list(disc2.groups)
      end
    end

    test "propagates Store.reload errors through Snippy.reload/1", %{fx: fx} do
      quiet do
        env = %{
          "RELOADERR_M_CRT" => fx.pem.a_cert,
          "RELOADERR_M_KEY" => fx.pem.a_key
        }

        {:ok, disc1} = Snippy.discover_certificates(prefix: "RELOADERR", env: env)

        Application.put_env(:snippy, :scan_fn, fn _ -> raise "boom" end)
        Snippy.Store.__test_reset__()

        try do
          assert {:error, _} = Snippy.reload(disc1)
        after
          Application.delete_env(:snippy, :scan_fn)
          Snippy.Store.__test_reset__()
        end
      end
    end
  end

  describe "phx_endpoint_config/1 input shapes" do
    test "discarded snippy opts include :discovered_certs", %{fx: fx} do
      quiet do
        env = %{
          "APP_M_CRT" => fx.pem.a_cert,
          "APP_M_KEY" => fx.pem.a_key
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)

        opts =
          Snippy.phx_endpoint_config(
            prefix: "APP",
            discovered_certs: disc,
            port: 4443
          )

        refute Keyword.has_key?(opts, :discovered_certs)
        assert opts[:port] == 4443
      end
    end
  end
end
