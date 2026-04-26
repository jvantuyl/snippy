defmodule Snippy.StoreTest do
  @moduledoc """
  Exercises the shared `Snippy.Store` path: ETS-backed scan + materialize
  memoization, host index, scheduled reload, and scan-task failure modes.

  These tests use real OS env vars (set/cleared per test) so they go
  through the production `lookup_groups`/`ensure_scanned` path. They are
  `async: false` and reset the Store between cases.
  """

  use ExUnit.Case, async: false

  alias Snippy.Store
  alias Snippy.TestFixtures

  @table :snippy_certs

  setup do
    fx = TestFixtures.setup()
    snapshot = snapshot_env()
    Store.__test_reset__()

    on_exit(fn ->
      restore_env(snapshot)
      Application.delete_env(:snippy, :scan_fn)
      Application.delete_env(:snippy, :scan_timeout_ms)
      Store.__test_reset__()
      TestFixtures.cleanup(fx)
    end)

    %{fx: fx}
  end

  describe "ensure_scanned/1" do
    test "populates :scan_meta and scan rows on first call", %{fx: fx} do
      put_env("STA_M_CRT", fx.pem.a_cert)
      put_env("STA_M_KEY", fx.pem.a_key)

      :ok = Store.ensure_scanned([])

      assert [{:scan_meta, %{seq: seq}}] = :ets.lookup(@table, :scan_meta)
      assert is_integer(seq)
      assert scan_row_count() > 0
    end

    test "is idempotent — repeated calls don't rescan", %{fx: fx} do
      put_env("STB_M_CRT", fx.pem.a_cert)
      put_env("STB_M_KEY", fx.pem.a_key)

      :ok = Store.ensure_scanned([])
      [{:scan_meta, meta1}] = :ets.lookup(@table, :scan_meta)

      :ok = Store.ensure_scanned([])
      [{:scan_meta, meta2}] = :ets.lookup(@table, :scan_meta)

      assert meta1.seq == meta2.seq
      assert meta1.scanned_at == meta2.scanned_at
    end
  end

  describe "lookup_groups/2" do
    test "returns successful materialized groups", %{fx: fx} do
      put_env("STC_M_CRT", fx.pem.a_cert)
      put_env("STC_M_KEY", fx.pem.a_key)

      groups = Store.lookup_groups(["STC"], [])
      assert [g] = groups
      assert g.prefix == "STC"
      assert g.key == "M"
      assert is_map(g.ssl_payload)
    end

    test "drops groups whose materialization fails", %{fx: fx} do
      put_env("STD_GOOD_CRT", fx.pem.a_cert)
      put_env("STD_GOOD_KEY", fx.pem.a_key)
      put_env("STD_BAD_CRT", "not pem")
      put_env("STD_BAD_KEY", "still not pem")

      ExUnit.CaptureLog.capture_log(fn ->
        groups = Store.lookup_groups(["STD"], [])
        keys = Enum.map(groups, & &1.key) |> Enum.sort()
        assert keys == ["GOOD"]
      end)
    end

    test "memoizes successes — second call hits ETS, no re-decode", %{fx: fx} do
      put_env("STE_M_CRT", fx.pem.a_cert)
      put_env("STE_M_KEY", fx.pem.a_key)

      groups1 = Store.lookup_groups(["STE"], [])
      [{_, cached1}] = :ets.lookup(@table, {:materialized, "STE", "M"})

      groups2 = Store.lookup_groups(["STE"], [])
      [{_, cached2}] = :ets.lookup(@table, {:materialized, "STE", "M"})

      # The cached row is the *same* tuple (same struct identity is not
      # guaranteed across processes, but the contents must be equal and the
      # row was not rewritten). Easiest check: only one materialized row.
      assert cached1 == cached2
      assert length(groups1) == length(groups2)
      assert :ets.match(@table, {{:materialized, "STE", :_}, :_}) |> length() == 1
    end

    test "memoizes errors — only one log line per broken group", %{fx: fx} do
      _ = fx
      put_env("STF_BAD_CRT", "definitely not pem")
      put_env("STF_BAD_KEY", "neither is this")

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          # 3 calls; the error should be logged exactly once.
          _ = Store.lookup_groups(["STF"], [])
          _ = Store.lookup_groups(["STF"], [])
          _ = Store.lookup_groups(["STF"], [])
        end)

      occurrences = log |> String.split("STF\"/BAD") |> length() |> Kernel.-(1)
      assert occurrences == 1, "expected 1 error log, got #{occurrences}\nlog:\n#{log}"
    end
  end

  describe "host index" do
    test "exact and wild rows are populated on materialize success", %{fx: fx} do
      put_env("STG_A_CRT", fx.pem.a_cert)
      put_env("STG_A_KEY", fx.pem.a_key)
      put_env("STG_W_CRT", fx.pem.wild_cert)
      put_env("STG_W_KEY", fx.pem.wild_key)

      _ = Store.lookup_groups(["STG"], [])

      exact = :ets.match(@table, {{:exact, "STG", :_, :"$1"}, :_})
      wild = :ets.match(@table, {{:wild, "STG", :_, :"$1"}, :_})

      flat = fn rs -> rs |> Enum.map(&hd/1) end
      assert "a.example.com" in flat.(exact)
      assert ["wild", "example", "com"] in flat.(wild)
    end
  end

  describe "reload/1" do
    test "increments seq, drops materialized + host index rows", %{fx: fx} do
      put_env("STH_M_CRT", fx.pem.a_cert)
      put_env("STH_M_KEY", fx.pem.a_key)

      _ = Store.lookup_groups(["STH"], [])
      [{:scan_meta, %{seq: seq1}}] = :ets.lookup(@table, :scan_meta)
      assert :ets.lookup(@table, {:materialized, "STH", "M"}) != []

      :ok = Store.reload([])

      [{:scan_meta, %{seq: seq2}}] = :ets.lookup(@table, :scan_meta)
      assert seq2 > seq1
      # After reload, the materialized cache should be empty (until a
      # subsequent lookup re-materializes).
      assert :ets.lookup(@table, {:materialized, "STH", "M"}) == []
      assert :ets.match(@table, {{:exact, "STH", :_, :_}, :_}) == []
    end

    test "subsequent lookup re-materializes after reload", %{fx: fx} do
      put_env("STI_M_CRT", fx.pem.a_cert)
      put_env("STI_M_KEY", fx.pem.a_key)

      [g1] = Store.lookup_groups(["STI"], [])
      :ok = Store.reload([])
      [g2] = Store.lookup_groups(["STI"], [])

      assert g1.spki_fingerprint == g2.spki_fingerprint
    end
  end

  describe "discover/1" do
    test "without :env hits the shared Store path (ETS rows present after)", %{fx: fx} do
      put_env("STJ_M_CRT", fx.pem.a_cert)
      put_env("STJ_M_KEY", fx.pem.a_key)

      {:ok, disc} = Store.discover(prefix: "STJ")

      assert [g] = disc.groups
      assert g.prefix == "STJ"
      # Shared discover strips the payload from public groups; verify that.
      assert g.ssl_payload == nil
      # ETS row exists in the Store cache.
      assert :ets.lookup(@table, {:materialized, "STJ", "M"}) != []
    end

    test "with :env runs isolated, leaves ETS scan rows empty", %{fx: fx} do
      env = %{
        "ISOLATED_M_CRT" => fx.pem.a_cert,
        "ISOLATED_M_KEY" => fx.pem.a_key
      }

      {:ok, disc} = Store.discover(prefix: "ISOLATED", env: env)

      assert [g] = disc.groups
      assert g.prefix == "ISOLATED"
      # Isolated path preserves the payload directly on the returned group.
      assert is_map(g.ssl_payload)
      # Shared scan was never touched.
      assert :ets.lookup(@table, :scan_meta) == []
      assert scan_row_count() == 0
    end
  end

  describe "scan failure handling" do
    test "scan task crash is reported as {:error, {:scan_crashed, _}}" do
      Application.put_env(:snippy, :scan_fn, fn _opts ->
        raise "boom"
      end)

      # ensure_scanned -> synchronous_scan -> raises Snippy.Store.ScanError
      assert_raise Snippy.Store.ScanError, fn ->
        Store.ensure_scanned([])
      end
    end

    test "scan task timeout is reported as {:error, :scan_timeout}" do
      Application.put_env(:snippy, :scan_timeout_ms, 50)

      Application.put_env(:snippy, :scan_fn, fn _opts ->
        Process.sleep(2_000)
        []
      end)

      assert_raise Snippy.Store.ScanError, fn ->
        Store.ensure_scanned([])
      end
    end
  end

  describe "scheduled reload" do
    test "reload_interval_ms triggers a re-scan", %{fx: fx} do
      put_env("STK_M_CRT", fx.pem.a_cert)
      put_env("STK_M_KEY", fx.pem.a_key)

      {:ok, _disc} = Store.discover(prefix: "STK", reload_interval_ms: 50)
      [{:scan_meta, %{seq: seq1}}] = :ets.lookup(@table, :scan_meta)

      # Wait for at least one scheduled reload to fire.
      Process.sleep(150)

      [{:scan_meta, %{seq: seq2}}] = :ets.lookup(@table, :scan_meta)
      assert seq2 > seq1
    end
  end

  describe "Snippy.cowboy_opts/1 (no :env, real Store)" do
    test "produces working :sni_fun + :certs_keys for a prefix", %{fx: fx} do
      put_env("STL_M_CRT", fx.pem.a_cert)
      put_env("STL_M_KEY", fx.pem.a_key)

      opts = Snippy.cowboy_opts(prefix: "STL")
      assert is_function(opts[:sni_fun], 1)
      assert is_list(opts[:certs_keys])
      assert opts[:certs_keys] != []
    end
  end

  # ---------- helpers ----------

  defp put_env(name, value) do
    System.put_env(name, value)
  end

  defp snapshot_env do
    System.get_env()
    |> Enum.filter(fn {k, _} -> snippy_test_var?(k) end)
    |> Enum.into(%{})
  end

  defp restore_env(snapshot) do
    # Clear any vars we may have set during the test.
    System.get_env()
    |> Enum.each(fn {k, _} ->
      if snippy_test_var?(k) and not Map.has_key?(snapshot, k) do
        System.delete_env(k)
      end
    end)

    Enum.each(snapshot, fn {k, v} -> System.put_env(k, v) end)
  end

  # Test variables we set all start with one of these prefixes; ignore
  # anything else so we don't clobber developer environment.
  @test_prefixes ~w(STA STB STC STD STE STF STG STH STI STJ STK STL)

  defp snippy_test_var?(name) do
    Enum.any?(@test_prefixes, fn pfx -> String.starts_with?(name, pfx <> "_") end)
  end

  defp scan_row_count do
    :ets.match(@table, {{:scan, :_, :_}, :_}) |> length()
  end
end
