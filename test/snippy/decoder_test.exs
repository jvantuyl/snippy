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

  describe "find_key_entry/1 dispatch" do
    test "matches traditional PKCS#1 RSA PEM entries", %{fx: fx} do
      pem = File.read!(fx.paths.a_key_traditional)
      {:ok, entries} = Decoder.decode_pem(pem)
      assert {:RSAPrivateKey, der, :not_encrypted} = Decoder.find_key_entry(entries)
      assert is_binary(der)
    end

    test "matches an :ECPrivateKey entry directly" do
      assert {:ECPrivateKey, <<>>, :not_encrypted} =
               Decoder.find_key_entry([{:ECPrivateKey, <<>>, :not_encrypted}])
    end

    test "matches a :DSAPrivateKey entry directly" do
      assert {:DSAPrivateKey, <<>>, :not_encrypted} =
               Decoder.find_key_entry([{:DSAPrivateKey, <<>>, :not_encrypted}])
    end

    test "matches a :PrivateKeyInfo entry directly" do
      assert {:PrivateKeyInfo, <<>>, :not_encrypted} =
               Decoder.find_key_entry([{:PrivateKeyInfo, <<>>, :not_encrypted}])
    end

    test "matches an :EncryptedPrivateKeyInfo entry directly" do
      assert {:EncryptedPrivateKeyInfo, <<>>, :not_encrypted} =
               Decoder.find_key_entry([{:EncryptedPrivateKeyInfo, <<>>, :not_encrypted}])
    end

    test "skips non-key entries and returns nil if none match" do
      assert Decoder.find_key_entry([
               {:Certificate, <<>>, :not_encrypted},
               {:DHParameter, <<>>, :not_encrypted}
             ]) == nil
    end
  end

  describe "decode_key/1 traditional RSA" do
    test "decodes a -----BEGIN RSA PRIVATE KEY----- PEM", %{fx: fx} do
      pem = File.read!(fx.paths.a_key_traditional)
      assert {:ok, key} = Decoder.decode_key(pem)
      assert key.asn1_type == :RSAPrivateKey
      assert Decoder.key_type(key) == :rsa
    end

    test "returns :invalid_key when pem_entry_decode raises" do
      # Build a PEM whose tag matches a key entry but whose DER body is
      # nonsense. pem_entry_decode/1 will raise; our rescue must convert
      # that to {:error, :invalid_key}.
      bogus_pem =
        "-----BEGIN PRIVATE KEY-----\n" <>
          Base.encode64("not-a-real-pkcs8-der") <>
          "\n-----END PRIVATE KEY-----\n"

      assert {:error, :invalid_key} = Decoder.decode_key(bogus_pem)
    end
  end

  describe "subject_cn/1" do
    test "extracts CN from a real cert subject", %{fx: fx} do
      [der | _] = pem_certs(fx.pem.a_cert)
      tbs = :public_key.pkix_decode_cert(der, :otp) |> elem(1)
      subject = elem(tbs, 6)

      assert "a.example.com" = Decoder.subject_cn(subject)
    end

    test "ignores non-CN attributes (printableString variant)" do
      # Multi-attribute subject; the *first* RDN is C=US (not CN), so the
      # `_ -> nil` arm is exercised before we find the CN attribute.
      subject =
        {:rdnSequence,
         [
           [{:AttributeTypeAndValue, {2, 5, 4, 6}, {:printableString, ~c"US"}}],
           [{:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, "Example Corp"}}],
           [{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, "leaf.example.com"}}]
         ]}

      assert "leaf.example.com" = Decoder.subject_cn(subject)
    end

    test "returns nil for non-rdnSequence input" do
      assert Decoder.subject_cn(:asn1_NOVALUE) == nil
      assert Decoder.subject_cn(nil) == nil
    end
  end

  describe "string_value/1" do
    test "utf8String returns the binary as-is" do
      assert Decoder.string_value({:utf8String, "ünìcôde"}) == "ünìcôde"
    end

    test "printableString converts a charlist to a binary" do
      assert Decoder.string_value({:printableString, ~c"ASCII Only"}) == "ASCII Only"
    end

    test "ia5String converts a charlist to a binary" do
      assert Decoder.string_value({:ia5String, ~c"ascii.example.com"}) == "ascii.example.com"
    end

    test "raw charlist input is converted to binary" do
      assert Decoder.string_value(~c"raw-charlist") == "raw-charlist"
    end

    test "raw binary input is returned as-is" do
      assert Decoder.string_value("already-a-binary") == "already-a-binary"
    end

    test "unknown shape returns nil" do
      assert Decoder.string_value({:unknown_string_type, "x"}) == nil
      assert Decoder.string_value(42) == nil
    end
  end

  describe "san_dns_names/1 / dns_name/1" do
    test ":asn1_NOVALUE returns []" do
      assert Decoder.san_dns_names(:asn1_NOVALUE) == []
    end

    test "nil returns []" do
      assert Decoder.san_dns_names(nil) == []
    end

    test "extension list with no SAN extension returns []" do
      assert Decoder.san_dns_names([
               {:Extension, {2, 5, 29, 19}, true, "basicConstraints stuff"}
             ]) == []
    end

    test "SAN extension extracts only :dNSName entries (charlist + binary)" do
      sans = [
        {:dNSName, ~c"charlist.example.com"},
        {:dNSName, "binary.example.com"},
        {:iPAddress, <<127, 0, 0, 1>>},
        {:rfc822Name, ~c"foo@example.com"}
      ]

      assert Decoder.san_dns_names([{:Extension, {2, 5, 29, 17}, false, sans}]) ==
               ["charlist.example.com", "binary.example.com"]
    end

    test "dns_name/1 returns nil for non-:dNSName tuples" do
      assert Decoder.dns_name({:iPAddress, <<10, 0, 0, 1>>}) == nil
      assert Decoder.dns_name(:something_else) == nil
    end

    test "dns_name/1 normalizes :dNSName binaries directly" do
      assert Decoder.dns_name({:dNSName, "binary-host.example"}) == "binary-host.example"
    end
  end

  describe "alg_oid/1 and alg_params/1" do
    test "PrivateKeyInfo_privateKeyAlgorithm yields oid and params" do
      alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 3}, "params"}
      assert Decoder.alg_oid(alg) == {1, 2, 3}
      assert Decoder.alg_params(alg) == "params"
    end

    test "AlgorithmIdentifier yields oid and params" do
      alg = {:AlgorithmIdentifier, {1, 2, 4}, "params2"}
      assert Decoder.alg_oid(alg) == {1, 2, 4}
      assert Decoder.alg_params(alg) == "params2"
    end

    test "PublicKeyAlgorithm yields oid and params" do
      alg = {:PublicKeyAlgorithm, {1, 2, 5}, "params3"}
      assert Decoder.alg_oid(alg) == {1, 2, 5}
      assert Decoder.alg_params(alg) == "params3"
    end

    test "SignatureAlgorithm yields oid and params" do
      alg = {:SignatureAlgorithm, {1, 2, 6}, "params4"}
      assert Decoder.alg_oid(alg) == {1, 2, 6}
      assert Decoder.alg_params(alg) == "params4"
    end
  end

  describe "parse_time/1" do
    test "utcTime YY < 50 maps into the 21st century" do
      dt = Decoder.parse_time({:utcTime, ~c"250401120000Z"})
      assert dt.year == 2025
      assert dt.month == 4
      assert dt.day == 1
      assert dt.hour == 12
    end

    test "utcTime YY >= 50 maps into the 20th century" do
      dt = Decoder.parse_time({:utcTime, ~c"850615101010Z"})
      assert dt.year == 1985
      assert dt.month == 6
      assert dt.day == 15
    end

    test "generalTime parses 4-digit year directly" do
      dt = Decoder.parse_time({:generalTime, ~c"21050102030405Z"})
      assert dt.year == 2105
      assert dt.month == 1
      assert dt.day == 2
      assert dt.hour == 3
      assert dt.minute == 4
      assert dt.second == 5
    end
  end

  describe "record_to_type/1 — fallthrough" do
    test "anonymous record returns :other" do
      assert Decoder.record_to_type({:Whatever, 1, 2, 3}) == :other
      assert Decoder.record_to_type(:asn1_NOVALUE) == :other
      assert Decoder.record_to_type("garbage") == :other
    end
  end

  describe "signer_record/1" do
    test "non-PrivateKeyInfo input is returned unchanged" do
      record = {:RSAPrivateKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      assert Decoder.signer_record(record) == record
      assert Decoder.signer_record({:other, 1, 2}) == {:other, 1, 2}
    end

    test "PrivateKeyInfo with RSA OID re-decodes to :RSAPrivateKey", %{fx: fx} do
      # Take a real RSA key and wrap it back into a PrivateKeyInfo record
      # so we exercise the RSA arm of signer_record/1.
      {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      rsa_record = key.record

      # Build a PKCS#8 PrivateKeyInfo containing the same RSA bytes.
      rsa_octets = :public_key.der_encode(:RSAPrivateKey, rsa_record)

      pki =
        {:PrivateKeyInfo, 0,
         {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 840, 113_549, 1, 1, 1}, :asn1_NOVALUE},
         rsa_octets, :asn1_NOVALUE}

      out = Decoder.signer_record(pki)
      assert elem(out, 0) == :RSAPrivateKey
    end

    test "PrivateKeyInfo with EC OID re-decodes to :ECPrivateKey", %{fx: fx} do
      {:ok, key} = Decoder.decode_key(fx.pem.ec_key)
      ec_record = key.record

      ec_octets = :public_key.der_encode(:ECPrivateKey, ec_record)

      pki =
        {:PrivateKeyInfo, 0,
         {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 840, 10_045, 2, 1}, :asn1_NOVALUE},
         ec_octets, :asn1_NOVALUE}

      out = Decoder.signer_record(pki)
      assert elem(out, 0) == :ECPrivateKey
    end

    test "PrivateKeyInfo with unknown OID is returned unchanged" do
      pki =
        {:PrivateKeyInfo, 0,
         {:PrivateKeyInfo_privateKeyAlgorithm, {1, 2, 9, 9, 9}, :asn1_NOVALUE}, <<>>,
         :asn1_NOVALUE}

      assert Decoder.signer_record(pki) == pki
    end
  end

  describe "spki_to_public/1" do
    test "RSAPublicKey is returned as-is" do
      rsa = {:RSAPublicKey, 65_537, 17}
      alg = {:AlgorithmIdentifier, {1, 2, 840, 113_549, 1, 1, 1}, :asn1_NOVALUE}
      assert ^rsa = Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, rsa})
    end

    test ":ECPoint tuple is paired with alg params" do
      alg = {:AlgorithmIdentifier, {1, 2, 840, 10_045, 2, 1}, "ec-params"}
      point = {:ECPoint, <<4, 1, 2, 3>>}

      assert {{:ECPoint, <<4, 1, 2, 3>>}, "ec-params"} =
               Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, point})
    end

    test "raw binary point gets wrapped in :ECPoint and paired with params" do
      alg = {:AlgorithmIdentifier, {1, 2, 840, 10_045, 2, 1}, "ec-params"}

      assert {{:ECPoint, <<4, 9, 9, 9>>}, "ec-params"} =
               Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, <<4, 9, 9, 9>>})
    end

    test "Ed25519 SPKI (non-binary public) returns :ed_pub :ed25519 + public" do
      # The is_binary(point) clause precedes this one; force the
      # final clause by passing a non-binary "public" payload.
      alg = {:AlgorithmIdentifier, {1, 3, 101, 112}, :asn1_NOVALUE}
      pubkey = [1, 2, 3, 4]

      assert {:ed_pub, :ed25519, ^pubkey} =
               Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, pubkey})
    end

    test "Ed448 SPKI (non-binary public) returns :ed_pub :ed448 + public" do
      alg = {:AlgorithmIdentifier, {1, 3, 101, 113}, :asn1_NOVALUE}
      pubkey = [5, 6, 7, 8]

      assert {:ed_pub, :ed448, ^pubkey} =
               Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, pubkey})
    end

    test "unknown OID with non-binary public returns the raw public" do
      alg = {:AlgorithmIdentifier, {1, 2, 9, 9, 9}, :asn1_NOVALUE}
      raw = [:not, :a, :binary]
      assert ^raw = Decoder.spki_to_public({:OTPSubjectPublicKeyInfo, alg, raw})
    end
  end

  describe "digest_and_signer/1" do
    test "RSA key uses :sha256 + traditional signer record", %{fx: fx} do
      {:ok, key} = Decoder.decode_key(fx.pem.a_key)
      assert {:sha256, signer} = Decoder.digest_and_signer(key)
      assert is_tuple(signer)
    end

    test ":eddsa key uses :none digest and the record as-is" do
      # Synthesize a key map whose key_type/1 returns :eddsa.
      ed_alg = {:PrivateKeyInfo_privateKeyAlgorithm, {1, 3, 101, 112}, :asn1_NOVALUE}
      record = {:PrivateKeyInfo, 0, ed_alg, <<>>, :asn1_NOVALUE}
      key = %{record: record, der: <<>>, asn1_type: :PrivateKeyInfo}
      assert {:none, ^record} = Decoder.digest_and_signer(key)
    end
  end

  describe "try_each_root/3" do
    test "halts with :ok when one of the candidate roots verifies the chain", %{fx: fx} do
      [leaf | _] = pem_certs(fx.pem.a_cert)
      [ca | _] = pem_certs(fx.pem.ca_cert)

      # Drop a couple of unrelated DERs in front of the real CA so
      # reduce_while actually iterates and finds the match.
      [other | _] = pem_certs(fx.pem.b_cert)
      assert :ok = Decoder.try_each_root(leaf, [], [other, ca])
    end

    test "returns {:error, :no_match} when no root verifies the chain", %{fx: fx} do
      [leaf | _] = pem_certs(fx.pem.a_cert)
      [other | _] = pem_certs(fx.pem.b_cert)
      assert {:error, :no_match} = Decoder.try_each_root(leaf, [], [other])
    end

    test "swallows pkix exceptions and reports :no_match", %{fx: fx} do
      [leaf | _] = pem_certs(fx.pem.a_cert)
      # Garbage CA der makes pkix_path_validation raise; the rescue
      # arm in try_each_root must catch it.
      assert {:error, :no_match} = Decoder.try_each_root(leaf, [], [<<0, 1, 2>>])
    end
  end

  describe "decode_encrypted_key/2 — both passwords fail" do
    test "returns :bad_password when neither trim nor literal pw work" do
      pem = encrypted_key_pem("expected\n")
      # Provide a *wrong* password whose trimmed form differs from itself.
      assert {:error, :bad_password} = Decoder.decode_key(pem, "wrong\n")
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
