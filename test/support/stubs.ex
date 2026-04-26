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

  defmodule DecoderCastoreOk do
    @moduledoc false
    # Decoder stand-in whose validate_against_castore/2 always returns
    # :ok, so the public-CA-validated success log line in
    # Snippy.Discovery.try_public_ca/4 is exercised. All other Decoder
    # functions used by Discovery delegate back to the real module.
    def validate_against_castore(_leaf, _intermediates), do: :ok

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
