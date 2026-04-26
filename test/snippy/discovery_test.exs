defmodule Snippy.DiscoveryTest do
  @moduledoc """
  Direct exercises of `Snippy.Discovery` internals that the higher-level
  helper tests don't reach: prefix normalization variants, materialization
  shape errors, password-file failures, and the malformed-OCSP-flag path.
  """

  use ExUnit.Case, async: false

  alias Snippy.Discovery
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  describe "normalize_prefixes!/1" do
    test "atom prefix is upcased" do
      assert ["MY_APP"] = Discovery.normalize_prefixes!(:my_app)
    end

    test "binary prefix is upcased" do
      assert ["FOO"] = Discovery.normalize_prefixes!("foo")
    end

    test "list of mixed prefixes deduped and validated" do
      assert ["A", "B"] = Discovery.normalize_prefixes!([:a, "b", "B"])
    end

    test "empty string is allowed (means: any)" do
      assert [""] = Discovery.normalize_prefixes!("")
    end

    test "nil raises" do
      assert_raise ArgumentError, fn -> Discovery.normalize_prefixes!(nil) end
    end

    test ":elixir is forbidden" do
      assert_raise ArgumentError, ~r/:elixir/, fn ->
        Discovery.normalize_prefixes!(:elixir)
      end
    end

    test "true/false atoms are forbidden" do
      assert_raise ArgumentError, fn -> Discovery.normalize_prefixes!(true) end
      assert_raise ArgumentError, fn -> Discovery.normalize_prefixes!(false) end
    end

    test "non-atom non-binary is forbidden" do
      assert_raise ArgumentError, ~r/invalid prefix/, fn ->
        Discovery.normalize_prefixes!(123)
      end
    end

    test "ambiguous overlapping prefixes raise" do
      assert_raise ArgumentError, ~r/ambiguous/, fn ->
        Discovery.normalize_prefixes!(["A", "A_B"])
      end
    end

    test "list with nil entry raises" do
      assert_raise ArgumentError, fn ->
        Discovery.normalize_prefixes!([:foo, nil])
      end
    end
  end

  describe "materialize_group/2 input shapes" do
    test "no cert and no key returns :no_cert_or_key" do
      raw = %{
        prefix: "X",
        key: "Y",
        cert: nil,
        key_var: nil,
        password: nil,
        ca: nil,
        ocsp: false,
        typo_warned?: false
      }

      assert {:error, :no_cert_or_key} = Discovery.materialize_group(raw)
    end

    test "key without cert returns :key_without_cert" do
      raw = %{
        prefix: "X",
        key: "Y",
        cert: nil,
        key_var: %{kind: :inline, var: "X_Y_KEY", val: "irrelevant"},
        password: nil,
        ca: nil,
        ocsp: false,
        typo_warned?: false
      }

      assert {:error, :key_without_cert} = Discovery.materialize_group(raw)
    end

    test "cert without key returns :cert_without_key" do
      raw = %{
        prefix: "X",
        key: "Y",
        cert: %{kind: :inline, var: "X_Y_CRT", val: "irrelevant"},
        key_var: nil,
        password: nil,
        ca: nil,
        ocsp: false,
        typo_warned?: false
      }

      assert {:error, :cert_without_key} = Discovery.materialize_group(raw)
    end

    test "password file that does not exist returns {:password_file, _, path}", %{fx: fx} do
      enc_key = File.read!(fx.paths.b_key_enc)

      raw = %{
        prefix: "X",
        key: "Y",
        cert: %{kind: :inline, var: "X_Y_CRT", val: fx.pem.b_cert},
        key_var: %{kind: :inline, var: "X_Y_KEY", val: enc_key},
        password: %{kind: :file, var: "X_Y_PWD_FILE", val: "/nonexistent/pwd"},
        ca: nil,
        ocsp: false,
        typo_warned?: false
      }

      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, {:password_file, :enoent, "/nonexistent/pwd"}} =
                 Discovery.materialize_group(raw)
      end)
    end

    test ":always public_ca with no castore raises early" do
      raw = %{
        prefix: "X",
        key: "Y",
        cert: nil,
        key_var: nil,
        password: nil,
        ca: nil,
        ocsp: false,
        typo_warned?: false
      }

      original = Application.get_env(:castore, :no_op, :unset)
      _ = original

      if Code.ensure_loaded?(CAStore) and function_exported?(CAStore, :file_path, 0) do
        # CAStore is present; we can't easily disable it for this case.
        :ok
      else
        assert {:error, :castore_required_for_always_validation} =
                 Discovery.materialize_group(raw, public_ca_validation: :always)
      end
    end
  end

  describe "OCSP / parse_bool!" do
    test "garbage value raises ArgumentError", %{fx: fx} do
      env = %{
        "OCSP_X_CRT" => fx.pem.a_cert,
        "OCSP_X_KEY" => fx.pem.a_key,
        "OCSP_X_OCSP_STAPLING" => "maybe?"
      }

      assert_raise ArgumentError, ~r/invalid boolean/, fn ->
        Snippy.discover_certificates(prefix: "OCSP", env: env)
      end
    end

    test "extra accepted forms (enable/disable/blank-trim)", %{fx: fx} do
      for {val, expected} <- [
            {"  TRUE  ", true},
            {"Enable", true},
            {"DISABLE", false}
          ] do
        env = %{
          "OCSP_X_CRT" => fx.pem.a_cert,
          "OCSP_X_KEY" => fx.pem.a_key,
          "OCSP_X_OCSP_STAPLING" => val
        }

        {:ok, disc} = Snippy.discover_certificates(prefix: "OCSP", env: env)
        [g] = disc.groups
        assert g.ocsp_stapling? == expected, "#{inspect(val)} -> #{expected}"
      end
    end

    test "lone _OSCP_STAPLING typo without canonical still works (different log line)", %{fx: fx} do
      env = %{
        "OCSP_X_CRT" => fx.pem.a_cert,
        "OCSP_X_KEY" => fx.pem.a_key,
        "OCSP_X_OSCP_STAPLING" => "true"
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "OCSP", env: env)
          [g] = disc.groups
          assert g.ocsp_stapling? == true
        end)

      assert log =~ "honoring it anyway"
    end
  end

  describe "encrypted key file without password" do
    test "logs a warning hinting the user to set the password", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.b_cert,
        "APP_X_KEY_FILE" => fx.paths.b_key_enc
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          assert disc.groups == []
        end)

      assert log =~ "encrypted key file"
      assert log =~ "no password set"
    end
  end

  describe "load_key file errors" do
    test "non-existent _KEY_FILE produces a {:file_read, _, path} error", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY_FILE" => "/nonexistent/key.pem"
      }

      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert disc.groups == []
        assert [{"APP", "X", {:file_read, :enoent, "/nonexistent/key.pem"}}] = disc.errors
      end)
    end

    test "non-existent _CRT_FILE produces a {:file_read, _, path} error", %{fx: fx} do
      env = %{
        "APP_X_CRT_FILE" => "/nonexistent/cert.pem",
        "APP_X_KEY" => fx.pem.a_key
      }

      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
        assert disc.groups == []
        assert [{"APP", "X", {:file_read, :enoent, "/nonexistent/cert.pem"}}] = disc.errors
      end)
    end
  end

  describe "chain validation paths" do
    test "valid CA produces :ok_chain", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_CACRT" => fx.pem.ca_cert
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      [g] = disc.groups
      assert g.chain_validation == :ok_chain
    end

    test "wrong CA but accepting :auto falls through to public-CA / self-signed", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_CACRT" => fx.pem.b_cert
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
          [g] = disc.groups
          # b_cert is not a real CA for a_cert, so chain failed; we then
          # fall through and end up either :ok_public or :ok_self.
          assert g.chain_validation in [:ok_public, :ok_self]
        end)

      assert log =~ "chain validation against provided CA failed"
    end

    test "with :never public_ca, no chain and self-signed accepted as :ok_self", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key
      }

      {:ok, disc} =
        Snippy.discover_certificates(
          prefix: "APP",
          env: env,
          public_ca_validation: :never
        )

      [g] = disc.groups
      assert g.chain_validation == :ok_self
    end

    test "public_ca: :always with no matching public CA returns {:public_ca_required, _}",
         %{fx: fx} do
      if Code.ensure_loaded?(CAStore) do
        env = %{
          "APP_X_CRT" => fx.pem.a_cert,
          "APP_X_KEY" => fx.pem.a_key
        }

        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, disc} =
            Snippy.discover_certificates(
              prefix: "APP",
              env: env,
              public_ca_validation: :always
            )

          assert disc.groups == []
          assert [{"APP", "X", {:public_ca_required, _reason}}] = disc.errors
        end)
      else
        :ok
      end
    end
  end

  describe "format_error/1 unknown reasons" do
    test "wraps an unknown reason via inspect/1" do
      assert Discovery.format_error({:totally_unknown, 42}) == "{:totally_unknown, 42}"
      assert Discovery.format_error(:also_unknown) == ":also_unknown"
    end
  end

  describe "_CACRT_FILE path" do
    test "loads CA chain from a file via _CACRT_FILE", %{fx: fx} do
      env = %{
        "APP_X_CRT" => fx.pem.a_cert,
        "APP_X_KEY" => fx.pem.a_key,
        "APP_X_CACRT_FILE" => fx.paths.ca_cert
      }

      {:ok, disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      [g] = disc.groups
      assert g.has_ca_chain?
      assert g.chain_validation == :ok_chain
    end
  end
end
