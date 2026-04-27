defmodule Snippy.LoggingTest do
  @moduledoc """
  Tests for discovery logging emitted by config-building helpers.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Snippy.Store
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    snapshot = snapshot_env()
    Store.__test_reset__()

    on_exit(fn ->
      restore_env(snapshot)
      Application.delete_env(:snippy, :log_level)
      Store.__test_reset__()
      TestFixtures.cleanup(fx)
    end)

    %{fx: fx}
  end

  describe "log_discovery emits on first call" do
    test "ssl_opts logs announcement and group details at debug", %{fx: fx} do
      put_env("LOG_M_CRT", fx.pem.a_cert)
      put_env("LOG_M_KEY", fx.pem.a_key)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOG")
        end)

      assert log =~ "discovering certificates for prefix(es)"
      assert log =~ ~s("LOG")
      assert log =~ "1 group(s)"
      assert log =~ "group LOG/M"
      assert log =~ "hosts=["
      assert log =~ "key_type="
      assert log =~ "password=absent"
    end

    test "phx_endpoint_config logs at debug", %{fx: fx} do
      put_env("LOGP_M_CRT", fx.pem.a_cert)
      put_env("LOGP_M_KEY", fx.pem.a_key)

      log =
        capture_log([level: :debug], fn ->
          Snippy.phx_endpoint_config(prefix: "LOGP", port: 4443)
        end)

      assert log =~ "discovering certificates"
      assert log =~ "LOGP"
    end
  end

  describe "log_level option" do
    test "log_level: :info emits at info level", %{fx: fx} do
      put_env("LOGI_M_CRT", fx.pem.a_cert)
      put_env("LOGI_M_KEY", fx.pem.a_key)

      log =
        capture_log([level: :info], fn ->
          Snippy.ssl_opts(prefix: "LOGI", log_level: :info)
        end)

      assert log =~ "discovering certificates"
      assert log =~ "LOGI"
    end

    test "log_level: false suppresses all logging", %{fx: fx} do
      put_env("LOGN_M_CRT", fx.pem.a_cert)
      put_env("LOGN_M_KEY", fx.pem.a_key)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOGN", log_level: false)
        end)

      refute log =~ "discovering certificates"
      refute log =~ "group LOGN/"
    end

    test "log_level: :none suppresses all logging", %{fx: fx} do
      put_env("LOGX_M_CRT", fx.pem.a_cert)
      put_env("LOGX_M_KEY", fx.pem.a_key)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOGX", log_level: :none)
        end)

      refute log =~ "discovering certificates"
    end

    test "application env :log_level is used as default", %{fx: fx} do
      put_env("LOGA_M_CRT", fx.pem.a_cert)
      put_env("LOGA_M_KEY", fx.pem.a_key)
      Application.put_env(:snippy, :log_level, :warning)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOGA")
        end)

      # :warning level — should appear when capturing at :debug
      assert log =~ "discovering certificates"
    end

    test "per-call :log_level overrides application env", %{fx: fx} do
      put_env("LOGO_M_CRT", fx.pem.a_cert)
      put_env("LOGO_M_KEY", fx.pem.a_key)
      Application.put_env(:snippy, :log_level, :info)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOGO", log_level: false)
        end)

      refute log =~ "discovering certificates"
    end
  end

  describe "change suppression" do
    test "second identical call produces no log", %{fx: fx} do
      put_env("LOGS_M_CRT", fx.pem.a_cert)
      put_env("LOGS_M_KEY", fx.pem.a_key)

      capture_log([level: :debug], fn ->
        Snippy.ssl_opts(prefix: "LOGS")
      end)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LOGS")
        end)

      refute log =~ "discovering certificates"
    end

    test "different prefix scopes log independently", %{fx: fx} do
      put_env("LGS1_M_CRT", fx.pem.a_cert)
      put_env("LGS1_M_KEY", fx.pem.a_key)
      put_env("LGS2_M_CRT", fx.pem.b_cert)
      put_env("LGS2_M_KEY", fx.pem.b_key)

      capture_log([level: :debug], fn ->
        Snippy.ssl_opts(prefix: "LGS1")
      end)

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LGS2")
        end)

      assert log =~ "discovering certificates"
      assert log =~ "LGS2"
    end

    test "reload with same env does not re-log", %{fx: fx} do
      put_env("LGR_M_CRT", fx.pem.a_cert)
      put_env("LGR_M_KEY", fx.pem.a_key)

      capture_log([level: :debug], fn ->
        Snippy.ssl_opts(prefix: "LGR")
      end)

      Store.reload([])

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LGR")
        end)

      # Same certs after reload — fingerprint matches, no re-log.
      refute log =~ "discovering certificates"
    end

    test "reload with changed cert re-logs", %{fx: fx} do
      put_env("LGC_M_CRT", fx.pem.a_cert)
      put_env("LGC_M_KEY", fx.pem.a_key)

      capture_log([level: :debug], fn ->
        Snippy.ssl_opts(prefix: "LGC")
      end)

      # Swap in a different cert
      put_env("LGC_M_CRT", fx.pem.b_cert)
      put_env("LGC_M_KEY", fx.pem.b_key)
      Store.reload([])

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LGC")
        end)

      assert log =~ "discovering certificates"
      assert log =~ "LGC"
    end

    test "log_level: false does not update stored fingerprint", %{fx: fx} do
      put_env("LGF_M_CRT", fx.pem.a_cert)
      put_env("LGF_M_KEY", fx.pem.a_key)

      # Call with logging disabled
      capture_log([level: :debug], fn ->
        Snippy.ssl_opts(prefix: "LGF", log_level: false)
      end)

      # Now call with logging enabled — should log because fp was never stored
      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LGF")
        end)

      assert log =~ "discovering certificates"
    end
  end

  describe "discovered_certs path" do
    test "logs with prefix list derived from groups", %{fx: fx} do
      env = %{
        "LGD_M_CRT" => fx.pem.a_cert,
        "LGD_M_KEY" => fx.pem.a_key
      }

      log =
        capture_log([level: :debug], fn ->
          {:ok, disc} = Snippy.discover_certificates(prefix: "LGD", env: env)
          Snippy.ssl_opts(prefix: "LGD", discovered_certs: disc)
        end)

      assert log =~ "discovering certificates for prefix(es)"
      assert log =~ "LGD"
      assert log =~ "1 group(s)"
    end

    test "logs 'supplied discovery' when no groups have a prefix", %{fx: fx} do
      _ = fx
      # An empty discovery has no groups, so prefixes list is empty
      disc = %Snippy.Discovery{groups: [], errors: []}

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "NOPE", discovered_certs: disc)
        end)

      assert log =~ "building config from supplied discovery"
      assert log =~ "no groups"
    end
  end

  describe "empty discovery" do
    test "logs 'no groups' when nothing matches", %{fx: fx} do
      _ = fx

      log =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "NOPE_NOTHING")
        end)

      assert log =~ "no groups"
    end
  end

  describe "local fallback logging" do
    setup %{fx: fx} do
      Snippy.TableOwner.__test_hide_table__()

      on_exit(fn ->
        Snippy.TableOwner.__test_restore_table__()
      end)

      %{fx: fx}
    end

    test "logs on every call (no suppression without ETS)", %{fx: fx} do
      put_env("LFL_M_CRT", fx.pem.a_cert)
      put_env("LFL_M_KEY", fx.pem.a_key)

      log1 =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LFL")
        end)

      log2 =
        capture_log([level: :debug], fn ->
          Snippy.ssl_opts(prefix: "LFL")
        end)

      assert log1 =~ "discovering certificates"
      assert log2 =~ "discovering certificates"
    end
  end

  # ---------- helpers ----------

  defp put_env(name, value), do: System.put_env(name, value)

  defp snapshot_env do
    System.get_env()
    |> Enum.filter(fn {k, _} -> snippy_test_var?(k) end)
    |> Enum.into(%{})
  end

  defp restore_env(snapshot) do
    System.get_env()
    |> Enum.each(fn {k, _} ->
      if snippy_test_var?(k) and not Map.has_key?(snapshot, k) do
        System.delete_env(k)
      end
    end)

    Enum.each(snapshot, fn {k, v} -> System.put_env(k, v) end)
  end

  @test_prefixes ~w(LOG LOGP LOGI LOGN LOGX LOGA LOGO LOGS LGS1 LGS2 LGR LGC LGF LGD LFL)

  defp snippy_test_var?(name) do
    Enum.any?(@test_prefixes, fn pfx -> String.starts_with?(name, pfx <> "_") end)
  end
end
