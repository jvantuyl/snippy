defmodule Snippy.TestStubs do
  @moduledoc false
  # Tiny zero-dep stubs used with `rewire` to exercise hard-to-reach
  # branches in production code. We avoid pulling in mox just for this.

  defmodule CAStoreBadPath do
    @moduledoc false
    # CAStore stand-in whose file_path/0 points at a guaranteed
    # non-existent file. Used to drive Decoder.validate_against_castore
    # into its `{:error, {:castore, _}}` else clause.
    def file_path, do: "/nonexistent/snippy/castore/cacert.pem"
  end

  defmodule CAStoreUnavailable do
    @moduledoc false
    # CAStore stand-in that intentionally does NOT export file_path/0,
    # so `function_exported?(__MODULE__, :file_path, 0)` returns false
    # and `castore_available?/0` falls into its `true ->` branch.
    def some_other_thing, do: :ok
  end

  defmodule FakeTableOwner do
    @moduledoc false
    # TableOwner stand-in whose `table_name/0` returns an atom that no
    # ETS table is ever registered under. Used with `rewire` to drive
    # `Snippy.Store.current_scan/0` into its `:undefined ->` branch.
    def table_name, do: :snippy_no_such_table_for_tests
  end

  defmodule OldOtpInfo do
    @moduledoc false
    # OtpInfo stand-in used to exercise `Snippy.OTPCheck.check!/0`'s
    # runtime raise. Returns a current OTP-like value at module-compile
    # time (so the `if @otp_release < @min_otp -> raise CompileError`
    # guard on the rewired copy still passes) and only flips to a too-old
    # value when the test arms it via `arm/0`.
    @flag {__MODULE__, :armed}

    def arm, do: :persistent_term.put(@flag, true)
    def disarm, do: :persistent_term.erase(@flag)

    def release do
      case :persistent_term.get(@flag, false) do
        true -> 1
        false -> :erlang.system_info(:otp_release) |> List.to_integer()
      end
    end
  end

  defmodule DecoderRaisesFirstCertValidity do
    @moduledoc false
    # Decoder stand-in whose `cert_validity/1` raises `ArgumentError` on
    # the first call per process (driving `check_validity/3` into its
    # rescue clause) and then delegates to the real Decoder so
    # `build_group_struct/6`'s second call still returns real validity
    # bounds. Reset between tests with `reset/0`.
    @flag {__MODULE__, :raised}

    def reset, do: Process.delete(@flag)

    def cert_validity(leaf) do
      case Process.get(@flag) do
        true ->
          Snippy.Decoder.cert_validity(leaf)

        _ ->
          Process.put(@flag, true)
          raise ArgumentError, "test-induced cert_validity failure"
      end
    end

    defdelegate decode_certs(pem), to: Snippy.Decoder
    defdelegate decode_certs_file(path), to: Snippy.Decoder
    defdelegate decode_key(pem, password), to: Snippy.Decoder
    defdelegate decode_key_file(path, password), to: Snippy.Decoder
    defdelegate cert_key_match?(leaf, key), to: Snippy.Decoder
    defdelegate cert_hostnames(leaf), to: Snippy.Decoder
    defdelegate spki_fingerprint(leaf), to: Snippy.Decoder
    defdelegate key_fingerprint(key), to: Snippy.Decoder
    defdelegate key_type(key), to: Snippy.Decoder
    defdelegate validate_chain(leaf, intermediates), to: Snippy.Decoder
    defdelegate validate_against_castore(leaf, intermediates), to: Snippy.Decoder
  end

  defmodule DecoderCastoreOk do
    @moduledoc false
    # Decoder stand-in whose validate_against_castore/2 always returns
    # :ok, so the public-CA-validated success log line in
    # Snippy.Discovery.try_public_ca/4 is exercised. All other Decoder
    # functions used by Discovery delegate back to the real module.
    @spec validate_against_castore(any(), any()) ::
            :ok | {:error, {:castore, atom()}}
    def validate_against_castore(_leaf, _intermediates) do
      # The opaque `:persistent_term.get/2` call defeats the type
      # system's narrowing of this function to `dynamic(:ok)`, so the
      # rewired Discovery's `{:error, reason}` clause stays type-safe.
      case :persistent_term.get({__MODULE__, :force_error}, :no) do
        :no -> :ok
        reason -> {:error, {:castore, reason}}
      end
    end

    defdelegate decode_certs(pem), to: Snippy.Decoder
    defdelegate decode_certs_file(path), to: Snippy.Decoder
    defdelegate decode_key(pem, password), to: Snippy.Decoder
    defdelegate decode_key_file(path, password), to: Snippy.Decoder
    defdelegate cert_key_match?(leaf, key), to: Snippy.Decoder
    defdelegate cert_validity(leaf), to: Snippy.Decoder
    defdelegate cert_hostnames(leaf), to: Snippy.Decoder
    defdelegate spki_fingerprint(leaf), to: Snippy.Decoder
    defdelegate key_fingerprint(key), to: Snippy.Decoder
    defdelegate key_type(key), to: Snippy.Decoder
    defdelegate validate_chain(leaf, intermediates), to: Snippy.Decoder
  end
end
