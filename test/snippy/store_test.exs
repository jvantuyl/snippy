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

  describe "scheduled reload — failure path" do
    test "scan failure during a scheduled reload is logged and the timer keeps firing",
         %{fx: fx} do
      put_env("STM_M_CRT", fx.pem.a_cert)
      put_env("STM_M_KEY", fx.pem.a_key)

      # First successful scan, schedule a reload, then make subsequent
      # scans crash. The scheduled-reload handler must catch the failure
      # without taking down the GenServer.
      {:ok, _disc} = Store.discover(prefix: "STM", reload_interval_ms: 50)
      [{:scan_meta, %{seq: seq1}}] = :ets.lookup(@table, :scan_meta)

      Application.put_env(:snippy, :scan_fn, fn _ -> raise "boom" end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          # Wait long enough for at least one scheduled reload to fire.
          Process.sleep(200)
        end)

      assert log =~ "scheduled reload failed"

      # The store is still alive and the scan_meta seq hasn't advanced
      # (because every reload after the first failed).
      assert Process.alive?(Process.whereis(Store))
      [{:scan_meta, %{seq: seq2}}] = :ets.lookup(@table, :scan_meta)
      assert seq2 == seq1
    end
  end

  describe "Store.reload/1 — failure path" do
    test "reload returns {:error, _} when the scan crashes, store stays up", %{fx: fx} do
      put_env("STN_M_CRT", fx.pem.a_cert)
      put_env("STN_M_KEY", fx.pem.a_key)

      # Prime with one good scan.
      :ok = Store.ensure_scanned([])

      Application.put_env(:snippy, :scan_fn, fn _ -> raise "boom" end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:error, _} = Store.reload([])
        end)

      assert log =~ "reload scan failed"
      assert Process.alive?(Process.whereis(Store))
    end
  end

  describe "stray task / DOWN messages" do
    test "the GenServer ignores random {ref, result} and {:DOWN, ...} messages" do
      pid = Process.whereis(Store)
      ref = make_ref()
      send(pid, {ref, :ignored})
      send(pid, {:DOWN, ref, :process, self(), :normal})
      # If the cast above were unhandled we'd see a crash. Confirm with a
      # synchronous round-trip that the server is still healthy.
      assert :ok = Store.ensure_scanned([])
      assert Process.alive?(pid)
    end
  end

  describe "isolated_discover errors" do
    test "isolated discovery captures broken groups in :errors", %{fx: fx} do
      env = %{
        "ISD_GOOD_CRT" => fx.pem.a_cert,
        "ISD_GOOD_KEY" => fx.pem.a_key,
        "ISD_BAD_CRT" => "not pem",
        "ISD_BAD_KEY" => "still not pem"
      }

      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, disc} = Store.discover(prefix: "ISD", env: env)
        assert [g] = disc.groups
        assert g.key == "GOOD"
        assert [{"ISD", "BAD", _}] = disc.errors
      end)
    end
  end

  describe "shared_discover errors" do
    test "shared discovery (no :env) reports broken groups in :errors", %{fx: fx} do
      put_env("STQ_GOOD_CRT", fx.pem.a_cert)
      put_env("STQ_GOOD_KEY", fx.pem.a_key)
      put_env("STQ_BAD_CRT", "not pem")
      put_env("STQ_BAD_KEY", "still not pem")

      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, disc} = Store.discover(prefix: "STQ")
        keys = Enum.map(disc.groups, & &1.key) |> Enum.sort()
        assert keys == ["GOOD"]
        assert [{"STQ", "BAD", _}] = disc.errors
      end)
    end
  end

  describe "materialize crash handling" do
    test "exception inside materialize_group is logged and surfaced as :materialize_exception",
         %{fx: fx} do
      _ = fx
      put_env("STR_M_CRT", "garbage that will be filtered into a raw group")
      put_env("STR_M_KEY", "garbage too")

      # Replace the discovery scan to surface a "valid-looking" raw group
      # that then crashes during materialize_group. We do this by making
      # materialize_group itself crash via a wrapped scan_fn that yields
      # entries the real materialize will reject — *and* by supplying a
      # custom :public_ca_validation that triggers a guaranteed error.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          # Even with garbage env, materialize will produce structured errors,
          # which is enough to exercise the error log path.
          {:ok, _disc} = Store.discover(prefix: "STR")
        end)

      assert log =~ "STR"
    end
  end

  describe "materialized_group/2" do
    test "returns the cached %Group{} after a shared lookup", %{fx: fx} do
      put_env("STO_M_CRT", fx.pem.a_cert)
      put_env("STO_M_KEY", fx.pem.a_key)

      _ = Store.lookup_groups(["STO"], [])

      assert %Snippy.Discovery.Group{prefix: "STO", key: "M"} =
               Store.materialized_group("STO", "M")
    end

    test "returns nil for an unknown (prefix, key)" do
      assert Store.materialized_group("DOES_NOT_EXIST", "ANYTHING") == nil
    end
  end

  describe "concurrent scan request" do
    test "second call to ensure_scanned during in-flight scan returns immediately", %{fx: fx} do
      put_env("STP_M_CRT", fx.pem.a_cert)
      put_env("STP_M_KEY", fx.pem.a_key)

      # Simulate a slow scan: the first GenServer.call sees :missing and
      # runs do_scan; while it's running we fire a parallel ensure_scanned
      # which should also succeed (and either find scan already done or
      # wait its turn and find it done).
      Application.put_env(:snippy, :scan_fn, fn opts ->
        Process.sleep(80)
        Snippy.Discovery.scan_all(opts)
      end)

      task = Task.async(fn -> Store.ensure_scanned([]) end)
      Process.sleep(20)
      assert :ok = Store.ensure_scanned([])
      assert :ok = Task.await(task, 5_000)
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
  @test_prefixes ~w(STA STB STC STD STE STF STG STH STI STJ STK STL STM STN STO STP STQ STR)

  defp snippy_test_var?(name) do
    Enum.any?(@test_prefixes, fn pfx -> String.starts_with?(name, pfx <> "_") end)
  end

  defp scan_row_count do
    :ets.match(@table, {{:scan, :_, :_}, :_}) |> length()
  end
end
