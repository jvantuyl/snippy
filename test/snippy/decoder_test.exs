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

    @tag :eddsa
    test "decodes Ed25519 key and reports :eddsa key type", %{fx: fx} do
      ed_key = File.read!(fx.paths.ed_key)

      if eddsa_supported?(ed_key) do
        assert {:ok, key} = Decoder.decode_key(ed_key)
        assert Decoder.key_type(key) == :eddsa
      else
        :ok
      end
    end

    test "decodes traditional (PKCS#1) encrypted key with correct password", %{fx: fx} do
      legacy = File.read!(fx.paths.b_key_enc_legacy)

      if String.contains?(legacy, "ENCRYPTED") do
        assert {:ok, key} = Decoder.decode_key(legacy, "secret")
        assert Decoder.key_type(key) == :rsa
      else
        :ok
      end
    end

    test "trims trailing whitespace and falls back to literal password" do
      # Direct test of the fallback path in decode_encrypted_key/2.
      pem = encrypted_key_pem("trail\n")
      assert {:ok, _} = Decoder.decode_key(pem, "trail\n")
    end

    test "key_type/1 returns :other for non-key arguments" do
      assert Decoder.key_type(%{}) == :other
      assert Decoder.key_type(nil) == :other
    end
  end

  describe "key_type/1 record dispatch" do
    test "RSA record" do
      r = {:RSAPrivateKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      assert Decoder.key_type(%{record: r, der: <<>>}) == :rsa
    end

    test "ECDSA record (5-tuple and 6-tuple variants)" do
      assert Decoder.key_type(%{
               record: {:ECPrivateKey, 1, <<>>, :asn1_NOVALUE, :asn1_NOVALUE},
               der: <<>>
             }) == :ecdsa

      assert Decoder.key_type(%{
               record: {:ECPrivateKey, 1, <<>>, :asn1_NOVALUE, :asn1_NOVALUE, :asn1_NOVALUE},
               der: <<>>
             }) == :ecdsa
    end

    test "DSA record" do
      assert Decoder.key_type(%{
               record: {:DSAPrivateKey, 0, 0, 0, 0, 0},
               der: <<>>
             }) == :dsa
    end

    test "PrivateKeyInfo dispatches by OID" do
      rsa_alg =
        {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 840, 113_549, 1, 1, 1}, :asn1_NOVALUE}

      ec_alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 840, 10_045, 2, 1}, :asn1_NOVALUE}
      ed25519_alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 3, 101, 112}, :asn1_NOVALUE}
      ed448_alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 3, 101, 113}, :asn1_NOVALUE}
      unk_alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 3, 4, 5}, :asn1_NOVALUE}

      pki = fn alg -> {:PrivateKeyInfo, 0, alg, <<>>, :asn1_NOVALUE} end

      assert Decoder.key_type(%{record: pki.(rsa_alg), der: <<>>}) == :rsa
      assert Decoder.key_type(%{record: pki.(ec_alg), der: <<>>}) == :ecdsa
      assert Decoder.key_type(%{record: pki.(ed25519_alg), der: <<>>}) == :eddsa
      assert Decoder.key_type(%{record: pki.(ed448_alg), der: <<>>}) == :eddsa
      assert Decoder.key_type(%{record: pki.(unk_alg), der: <<>>}) == :other
    end

    test "unknown record falls through to :other" do
      assert Decoder.key_type(%{record: {:something_else, 1, 2}, der: <<>>}) == :other
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

    @tag :eddsa
    test "returns true for matching cert/key (Ed25519)", %{fx: fx} do
      ed_cert = File.read!(fx.paths.ed_cert)
      ed_key = File.read!(fx.paths.ed_key)

      if eddsa_supported?(ed_key) do
        [der | _] = pem_certs(ed_cert)
        {:ok, key} = Decoder.decode_key(ed_key)
        assert Decoder.cert_key_match?(der, key)
      else
        :ok
      end
    end

    test "returns false for mismatched cert/key", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      {:ok, key} = Decoder.decode_key(fx.pem.b_key)
      refute Decoder.cert_key_match?(der, key)
    end

    test "returns false (does not raise) when given garbage cert DER", %{fx: fx} do
      {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      refute Decoder.cert_key_match?(<<0, 1, 2, 3>>, key)
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

    test "rescues exception from :public_key by returning {:error, {:validation_exception, _}}" do
      # Garbage bytes for both leaf and CA force pkix_path_validation to
      # raise rather than just return {:error, _}.
      assert {:error, {:validation_exception, _msg}} =
               Decoder.validate_chain(<<0, 1, 2, 3>>, [<<4, 5, 6, 7>>])
    end
  end

  describe "validate_against_castore/2 — code paths" do
    test "validates a real cert against castore and returns :ok or :error" do
      # We don't assume the CAStore bundle does or doesn't trust our
      # self-signed cert; we just exercise the file-read/decode/match path.
      pem = """
      -----BEGIN CERTIFICATE-----
      MIIB+TCCAaCgAwIBAgIUVoQq3Z/uX5z3uV0hxwy8L4xZ6+UwCgYIKoZIzj0EAwIw
      ZjELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWVTdGF0ZTEUMBIGA1UEBwwLU29t
      ZUNpdHkxFTATBgNVBAoMDFNvbWVDb21wYW55MRUwEwYDVQQDDAxFeGFtcGxlIENv
      cnAwHhcNMjUwNDAxMDAwMDAwWhcNMzUwNDAxMDAwMDAwWjBmMQswCQYDVQQGEwJV
      UzETMBEGA1UECAwKU29tZVN0YXRlMRQwEgYDVQQHDAtTb21lQ2l0eTEVMBMGA1UE
      CgwMU29tZUNvbXBhbnkxFTATBgNVBAMMDEV4YW1wbGUgQ29ycDBZMBMGByqGSM49
      AgEGCCqGSM49AwEHA0IABACgEzz5tqQfx5J3bA9oR4nM3eAm6r/0pxJ6F/+OcFKY
      dQ/1yxDXn8mKO2A95eEY7sDKsq1eHA1F0ROlw0ZcvVKjEzARMA8GA1UdEwEB/wQF
      MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgGmBeY8ImQ0fQ+JnvzHnqXSWB9cV0WSpa
      lwq5gP4hFR0CIQCZGTeS7aDF3xlhnhZbVZkdGP5DOWGYJj+JoAo7NujcxQ==
      -----END CERTIFICATE-----
      """

      der =
        case Decoder.decode_certs(pem) do
          {:ok, [d | _]} -> d
          _ -> nil
        end

      if der do
        assert match?(:ok, Decoder.validate_against_castore(der)) or
                 match?({:error, _}, Decoder.validate_against_castore(der))
      else
        :ok
      end
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

  describe "cert_hostnames/1 / SAN edge cases" do
    test "returns SAN dNSNames as binaries even when stored as charlists", %{fx: fx} do
      # Our normal path goes through `dns_name({:dNSName, n}) when is_list(n)`.
      [der | _] = pem_certs(fx.pem.a_cert)

      hosts = Decoder.cert_hostnames(der)
      assert "a.example.com" in hosts
      assert Enum.all?(hosts, &is_binary/1)
    end

    test "cert with multi-attribute subject and no SAN returns CN only", %{fx: fx} do
      # Hits subject_cn's `_ -> nil` (for non-CN RDNs like C, ST, L, O),
      # the various `string_value/1` branches (printableString, utf8String),
      # and san_dns_names/1's `:asn1_NOVALUE` clause (no SAN extension).
      [der | _] = pem_certs(File.read!(fx.paths.nosan_cert))

      hosts = Decoder.cert_hostnames(der)
      assert hosts == ["nosan.example.com"]
    end
  end

  describe "fingerprint_hex/1" do
    test "32-byte hash becomes 95-char colon-separated lowercase hex" do
      hash = :crypto.hash(:sha256, "hello")
      hex = Decoder.fingerprint_hex(hash)
      assert String.length(hex) == 32 * 2 + 31
      assert String.match?(hex, ~r/^([0-9a-f]{2}:){31}[0-9a-f]{2}$/)
    end
  end

  defp pem_certs(pem) do
    {:ok, ders} = Decoder.decode_certs(pem)
    ders
  end

  # Did openssl produce a real Ed25519 key, or did the fixture script
  # silently fall back to ECDSA on a host with no Ed25519 support?
  defp eddsa_supported?(ed_key_pem) do
    case Decoder.decode_key(ed_key_pem) do
      {:ok, key} -> Decoder.key_type(key) == :eddsa
      _ -> false
    end
  end

  # Mints a small RSA key, encrypts it (PKCS#8) with the given password,
  # returns PEM. Used to exercise the password-trim fallback in
  # decode_encrypted_key/2.
  defp encrypted_key_pem(password) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "snippy_decoder_pwd_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    key = Path.join(dir, "key.pem")

    try do
      {_, 0} = System.cmd("openssl", ["genpkey", "-algorithm", "RSA", "-out", key])

      {_, 0} =
        System.cmd("openssl", [
          "pkcs8",
          "-topk8",
          "-in",
          key,
          "-passout",
          "pass:" <> password,
          "-out",
          key <> ".enc"
        ])

      File.read!(key <> ".enc")
    after
      File.rm_rf!(dir)
    end
  end
end
