defmodule Snippy.RewireTest do
  @moduledoc """
  Coverage-completion tests that swap module dependencies with `rewire` to
  drive code paths that depend on environment conditions we can't otherwise
  produce (a missing CAStore, a passing public-CA validation, a CAStore
  whose bundle file isn't readable).
  """

  use ExUnit.Case, async: false
  import Rewire

  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  test "Decoder.validate_against_castore wraps File.read error as {:castore, _}",
       %{fx: fx} do
    {:ok, [leaf | _]} = Snippy.Decoder.decode_certs(fx.pem.a_cert)

    rewire Snippy.Decoder, CAStore: Snippy.TestStubs.CAStoreBadPath, as: BadDecoder do
      assert {:error, {:castore, :enoent}} = BadDecoder.validate_against_castore(leaf)
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
end
