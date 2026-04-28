defmodule Snippy.RewireTest do
  @moduledoc """
  Coverage-completion tests that swap module dependencies with `rewire` to
  drive code paths that depend on environment conditions we can't otherwise
  produce (a missing CAStore, a passing public-CA validation, a CAStore
  whose bundle file isn't readable, an OTP version below the minimum, an
  ETS table that has been torn down out from under us, etc.).
  """

  use ExUnit.Case, async: false
  import Rewire
  import Snippy.TestUtil

  alias Snippy.TestFixtures
  alias Snippy.TestStubs

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  test "Decoder.validate_against_castore wraps File.read error as {:castore, _}",
       %{fx: fx} do
    quiet do
      {:ok, [leaf | _]} = Snippy.Decoder.decode_certs(fx.pem.a_cert)

      rewire Snippy.Decoder, CAStore: Snippy.TestStubs.CAStoreBadPath, as: BadDecoder do
        assert {:error, {:castore, :enoent}} = BadDecoder.validate_against_castore(leaf)
      end
    end
  end

  test "Discovery.try_public_ca logs success and returns :ok_public when castore validates",
       %{fx: fx} do
    rewire Snippy.Discovery,
      Decoder: Snippy.TestStubs.DecoderCastoreOk,
      as: OkDiscovery do
      env = %{
        "PUB_X_CRT" => fx.pem.a_cert,
        "PUB_X_KEY" => fx.pem.a_key
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          # Call the rewired Discovery directly so the Decoder swap takes
          # effect; the Snippy.discover_certificates wrapper still uses the
          # un-rewired module.
          entries = OkDiscovery.scan_all(env: env)

          [raw] =
            entries |> OkDiscovery.filter_by_prefixes(["PUB"]) |> OkDiscovery.group_entries()

          assert {:ok, g} = OkDiscovery.materialize_group(raw)
          assert g.chain_validation == :ok_public
        end)

      assert log =~ "validated against public CA bundle"
    end
  end

  test "Discovery.try_public_ca falls through to self-signed when CAStore is unavailable",
       %{fx: fx} do
    rewire Snippy.Discovery,
      CAStore: Snippy.TestStubs.CAStoreUnavailable,
      as: NoCAStoreDiscovery do
      env = %{
        "NOCA_X_CRT" => fx.pem.a_cert,
        "NOCA_X_KEY" => fx.pem.a_key
      }

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          entries = NoCAStoreDiscovery.scan_all(env: env)

          [raw] =
            entries
            |> NoCAStoreDiscovery.filter_by_prefixes(["NOCA"])
            |> NoCAStoreDiscovery.group_entries()

          assert {:ok, g} = NoCAStoreDiscovery.materialize_group(raw)
          assert g.chain_validation == :ok_self
        end)

      # Self-signed log fires; "validated against public CA bundle" and
      # "public CA validation failed" must NOT appear because the cond
      # short-circuits before any public-CA attempt.
      assert log =~ "no chain validation"
      refute log =~ "validated against public CA"
      refute log =~ "public CA validation failed"
    end
  end

  test "Discovery.check_validity rescues ArgumentError raised from cert_validity",
       %{fx: fx} do
    quiet do
      rewire Snippy.Discovery,
        Decoder: Snippy.TestStubs.DecoderRaisesFirstCertValidity,
        as: D do
        TestStubs.DecoderRaisesFirstCertValidity.reset()

        try do
          env = %{
            "RAISE_X_CRT" => fx.pem.a_cert,
            "RAISE_X_KEY" => fx.pem.a_key
          }

          entries = D.scan_all(env: env)

          [raw] =
            entries
            |> D.filter_by_prefixes(["RAISE"])
            |> D.group_entries()

          # First Decoder.cert_validity/1 call (inside check_validity/3)
          # raises ArgumentError; the rescue clause turns it into :ok and
          # the `with` continues, so the group materializes successfully
          # using the second (real) cert_validity call inside
          # build_group_struct/6.
          assert {:ok, g} = D.materialize_group(raw)
          assert g.prefix == "RAISE"
          assert g.key == "X"
          assert %DateTime{} = g.not_before
          assert %DateTime{} = g.not_after
        after
          TestStubs.DecoderRaisesFirstCertValidity.reset()
        end
      end
    end
  end

  test "OTPCheck.check! raises when the running OTP release is below @min_otp" do
    rewire Snippy.OTPCheck, OtpInfo: Snippy.TestStubs.OldOtpInfo, as: OldCheck do
      TestStubs.OldOtpInfo.arm()

      try do
        assert_raise RuntimeError, ~r/Snippy requires OTP/, fn ->
          OldCheck.check!()
        end
      after
        TestStubs.OldOtpInfo.disarm()
      end
    end
  end

  test "Store.current_scan returns :missing when @table is absent" do
    # FakeTableOwner.table_name/0 returns an atom no ETS table is ever
    # registered under, so the rewired Store's compile-time
    # `@table = TableOwner.table_name()` resolves to that bogus name. A
    # subsequent `:ets.whereis(@table)` returns `:undefined`, exercising
    # the `:undefined ->` branch in `current_scan/0`. The follow-on
    # `synchronous_scan/1` then exits :noproc because we never start a
    # GenServer for the rewired copy.
    rewire Snippy.Store, TableOwner: Snippy.TestStubs.FakeTableOwner, as: NoTableStore do
      assert {:noproc, _} = catch_exit(NoTableStore.ensure_scanned([]))
    end
  end

  test "Store.__test_reset__ rescues ArgumentError when @table has been torn down" do
    quiet do
      Snippy.TableOwner.__test_hide_table__()

      try do
        # All :ets calls inside the handle_call body raise ArgumentError
        # because the table has been renamed away; the surrounding
        # try/rescue catches that and the call still returns :ok.
        assert :ok = Snippy.Store.__test_reset__()
        assert Process.alive?(Process.whereis(Snippy.Store))
      after
        Snippy.TableOwner.__test_restore_table__()
      end
    end
  end
end
