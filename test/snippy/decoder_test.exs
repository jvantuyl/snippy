defmodule Snippy.DecoderTest do
  use ExUnit.Case, async: false

  alias Snippy.Decoder
  alias Snippy.TestFixtures

  setup do
    fx = TestFixtures.setup()
    on_exit(fn -> TestFixtures.cleanup(fx) end)
    %{fx: fx}
  end

  describe "decode_pem/1" do
    test "returns :invalid_pem for non-PEM input" do
      assert {:error, :invalid_pem} = Decoder.decode_pem("not pem at all")
    end

    test "decodes a valid PEM cert", %{fx: fx} do
      assert {:ok, [{:Certificate, _der, :not_encrypted} | _]} = Decoder.decode_pem(fx.pem.a_cert)
    end
  end

  describe "decode_pem_file/1" do
    test "returns :file_read on missing path" do
      assert {:error, {:file_read, :enoent, "/nonexistent/path"}} =
               Decoder.decode_pem_file("/nonexistent/path")
    end

    test "decodes a valid PEM file", %{fx: fx} do
      assert {:ok, _entries} = Decoder.decode_pem_file(fx.paths.a_cert)
    end
  end

  describe "decode_certs/1" do
    test "returns :no_certificates_found for PEM without certs", %{fx: fx} do
      assert {:error, :no_certificates_found} = Decoder.decode_certs(fx.pem.a_key)
    end

    test "decodes single-cert PEM into a list of DERs", %{fx: fx} do
      assert {:ok, [der | _]} = Decoder.decode_certs(fx.pem.a_cert)
      assert is_binary(der)
    end
  end

  describe "decode_key/2" do
    test "returns :no_key_found for PEM without keys", %{fx: fx} do
      assert {:error, :no_key_found} = Decoder.decode_key(fx.pem.a_cert)
    end

    test "decodes an unencrypted RSA key", %{fx: fx} do
      assert {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      assert key.asn1_type in [:RSAPrivateKey, :PrivateKeyInfo]
      assert is_binary(key.der)
      assert Decoder.key_type(key) == :rsa
    end

    test "decodes an encrypted key with the correct password", %{fx: fx} do
      assert {:ok, _} = Decoder.decode_key(File.read!(fx.paths.b_key_enc), "secret")
    end

    test "rejects encrypted key with no password", %{fx: fx} do
      assert {:error, :encrypted_key_no_password} =
               Decoder.decode_key(File.read!(fx.paths.b_key_enc))
    end

    test "rejects encrypted key with wrong password", %{fx: fx} do
      assert {:error, :bad_password} =
               Decoder.decode_key(File.read!(fx.paths.b_key_enc), "wrong")
    end

    test "decodes ECDSA key and reports :ecdsa key type", %{fx: fx} do
      assert {:ok, key} = Decoder.decode_key(fx.pem.ec_key)
      assert Decoder.key_type(key) == :ecdsa
    end
  end

  describe "cert_validity/1 and cert_valid_now?/1" do
    test "valid cert is currently valid", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      assert Decoder.cert_valid_now?(der)
      {nb, na} = Decoder.cert_validity(der)
      assert DateTime.compare(nb, na) == :lt
    end

    test "expired cert is not currently valid", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.expired_cert)
      refute Decoder.cert_valid_now?(der)
    end
  end

  describe "cert_hostnames/1" do
    test "returns SAN dNSNames", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      assert "a.example.com" in Decoder.cert_hostnames(der)
    end

    test "returns wildcard SANs verbatim", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.wild_cert)
      assert "*.wild.example.com" in Decoder.cert_hostnames(der)
    end
  end

  describe "cert_key_match?/2" do
    test "returns true for matching cert/key (RSA)", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      assert Decoder.cert_key_match?(der, key)
    end

    test "returns true for matching cert/key (ECDSA)", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.ec_cert)
      {:ok, key} = Decoder.decode_key(fx.pem.ec_key)
      assert Decoder.cert_key_match?(der, key)
    end

    test "returns false for mismatched cert/key", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      {:ok, key} = Decoder.decode_key(fx.pem.b_key)
      refute Decoder.cert_key_match?(der, key)
    end
  end

  describe "fingerprints" do
    test "spki and key fingerprints are 32-byte SHA-256", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      assert byte_size(Decoder.spki_fingerprint(der)) == 32
      assert byte_size(Decoder.key_fingerprint(key)) == 32
    end

    test "fingerprint_hex is colon-separated lowercase hex", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      hex = Decoder.fingerprint_hex(Decoder.spki_fingerprint(der))
      assert hex =~ ~r/^([0-9a-f]{2}:){31}[0-9a-f]{2}$/
    end
  end

  describe "validate_chain/2" do
    test "returns :no_ca for an empty CA list", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      assert {:error, :no_ca} = Decoder.validate_chain(der, [])
    end

    test "validates a leaf against its issuing CA", %{fx: fx} do
      [leaf | _] = pem_certs(fx.pem.a_cert)
      [ca | _] = pem_certs(fx.pem.ca_cert)
      assert :ok = Decoder.validate_chain(leaf, [ca])
    end

    test "rejects leaf signed by a different CA", %{fx: fx} do
      # A wholly unrelated self-signed cert as the "anchor".
      [leaf | _] = pem_certs(fx.pem.a_cert)
      [other | _] = pem_certs(fx.pem.b_cert)
      assert {:error, _reason} = Decoder.validate_chain(leaf, [other])
    end
  end

  describe "validate_against_castore/2" do
    @tag :castore
    test "self-signed leaf is rejected by the public CA bundle", %{fx: fx} do
      if Code.ensure_loaded?(CAStore) do
        [leaf | _] = pem_certs(fx.pem.a_cert)

        case Decoder.validate_against_castore(leaf) do
          {:error, _reason} -> :ok
          :ok -> flunk("self-signed leaf unexpectedly validated against public CAs")
        end
      else
        :ok
      end
    end
  end

  describe "format_error/1" do
    test "covers each known reason" do
      cases = [
        {{:file_read, :enoent, "/x"}, ~r{cannot read /x}},
        {{:password_file, :enoent, "/p"}, ~r{password file /p}},
        {:invalid_pem, ~r{invalid PEM}},
        {:no_certificates_found, ~r{no certificates}},
        {:no_key_found, ~r{no private key}},
        {:bad_password, ~r{wrong password}},
        {:encrypted_key_no_password, ~r{encrypted but no password}},
        {:cert_key_mismatch, ~r{cert public key}},
        {:no_cert_or_key, ~r{no cert or key}},
        {:key_without_cert, ~r{key present but}},
        {:cert_without_key, ~r{certificate present but}},
        {:castore_required_for_always_validation, ~r{:castore dependency}},
        {{:not_yet_valid, ~U[2099-01-01 00:00:00Z]}, ~r{not yet valid}},
        {{:expired, ~U[2000-01-01 00:00:00Z]}, ~r{expired}},
        {{:public_ca_required, :foo}, ~r{public CA validation required}}
      ]

      for {reason, pattern} <- cases do
        assert Snippy.Discovery.format_error(reason) =~ pattern,
               "format_error(#{inspect(reason)}) did not match #{inspect(pattern)}"
      end
    end

    test "falls back to inspect/1 for unknown reasons" do
      assert Snippy.Discovery.format_error({:totally_unknown, 42}) == "{:totally_unknown, 42}"
    end
  end

  defp pem_certs(pem) do
    {:ok, ders} = Decoder.decode_certs(pem)
    ders
  end
end
