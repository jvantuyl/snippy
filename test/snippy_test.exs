defmodule SnippyTest do
  use ExUnit.Case, async: false

  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  describe "discover_certificates/1" do
    test "discovers cert/key from inline PEM env vars", %{fx: fx} do
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
    end

    test "discovers from _FILE variants", %{fx: fx} do
      env = %{
        "APP_FOO_CRT_FILE" => fx.paths.a_cert,
        "APP_FOO_KEY_FILE" => fx.paths.a_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert [g] = disc.groups
      assert g.cert_source == :file
      assert g.key_source == :file
    end

    test "decrypts encrypted key with password", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.b_cert,
        "APP_X_KEY_FILE" => fx.paths.b_key_enc,
        "APP_X_PWD" => "secret"
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert [g] = disc.groups
      assert g.has_password?
    end

    test "trims trailing whitespace from password file", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.b_cert,
        "APP_X_KEY_FILE" => fx.paths.b_key_enc,
        "APP_X_PWD_FILE" => fx.paths.pwd_file
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert [_g] = disc.groups
    end

    test "drops group with bad password", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.b_cert,
        "APP_X_KEY_FILE" => fx.paths.b_key_enc,
        "APP_X_PWD" => "wrong"
      }

      {:ok, disc} =
        ExUnit.CaptureLog.with_log(fn ->
          Snippy.discover_certificates(prefix: "APP", env: env)
        end)
        |> elem(0)
        |> case do
          val -> val
        end

      assert disc.groups == []
    end

    test "drops expired cert", %{fx: fx} do
      env = %{
        "APP_OLD_CRT" => fx.pem.expired_cert,
        "APP_OLD_KEY" => fx.pem.expired_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert disc.groups == []
    end

    test "drops not-yet-valid cert", %{fx: fx} do
      env = %{
        "APP_NEW_CRT" => fx.pem.future_cert,
        "APP_NEW_KEY" => fx.pem.future_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert disc.groups == []
    end

    test "expiry_grace_seconds keeps recently-expired cert", %{fx: fx} do
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

    test "includes CA chain when CACRT is set", %{fx: fx} do
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

    test "discovers wildcard SAN cert", %{fx: fx} do
      env = %{
        "APP_W_CRT" => fx.pem.wild_cert,
        "APP_W_KEY" => fx.pem.wild_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert [g] = disc.groups
      assert "*.wild.example.com" in g.hostnames
    end

    test "discovers ECDSA cert and reports key_type", %{fx: fx} do
      env = %{
        "APP_EC_CRT" => fx.pem.ec_cert,
        "APP_EC_KEY" => fx.pem.ec_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      assert [g] = disc.groups
      assert g.key_type == :ecdsa
    end

    test "handles atom prefixes", %{fx: fx} do
      env = %{
        "MY_APP_MAIN_CRT" => fx.pem.a_cert,
        "MY_APP_MAIN_KEY" => fx.pem.a_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: :my_app, env: env)
      assert [_g] = disc.groups
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

  describe "OCSP stapling" do
    test "parses canonical _OCSP_STAPLING values", %{fx: fx} do
      for {val, expected} <- [
            {"true", true},
            {"on", true},
            {"enabled", true},
            {"1", true},
            {"false", false},
            {"off", false},
            {"disabled", false},
            {"0", false}
          ] do
        env = %{
          "APP_X_CRT" => fx.pem.a_cert,
          "APP_X_KEY" => fx.pem.a_key,
          "APP_X_OCSP_STAPLING" => val
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert [g] = disc.groups
        assert g.ocsp_stapling? == expected, "#{val} should parse to #{expected}"
      end
    end

    test "honors typo _OSCP_STAPLING with warning", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_OSCP_STAPLING" => "true"
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert [g] = disc.groups
          assert g.ocsp_stapling? == true
        end)

      assert log =~ "misspelling"
    end

    test "prefers canonical over typo when both set", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_OCSP_STAPLING" => "false",
        "APP_X_OSCP_STAPLING" => "true"
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          [g] = disc.groups
          assert g.ocsp_stapling? == false
        end)

      assert log =~ "misspelling"
    end
  end

  describe "phx_endpoint_config/2" do
    test "merges Phoenix transport opts with Snippy SSL opts", %{fx: fx} do
      env = %{
        "APP_MAIN_CRT" => fx.pem.a_cert,
        "APP_MAIN_KEY" => fx.pem.a_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)

      opts =
        Snippy.phx_endpoint_config(disc,
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

    test "passes :only/:keys through to scope filtering, not into the result", %{fx: fx} do
      env = %{
        "APP_MAIN_CRT" => fx.pem.a_cert,
        "APP_MAIN_KEY" => fx.pem.a_key
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)

      opts = Snippy.phx_endpoint_config(disc, port: 4443, only: ["a.example.com"])

      refute Keyword.has_key?(opts, :only)
      refute Keyword.has_key?(opts, :keys)
      assert opts[:port] == 4443
      assert is_function(opts[:sni_fun], 1)
    end
  end
end
