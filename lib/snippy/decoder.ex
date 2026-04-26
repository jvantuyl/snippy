defmodule Snippy.Decoder do
  @moduledoc false

  require Logger

  # ---------------------------------------------------------------- PEM I/O --

  def decode_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [] -> {:error, :invalid_pem}
      entries -> {:ok, entries}
    end
  end

  def decode_pem_file(path) when is_binary(path) do
    case File.read(path) do
      {:ok, contents} -> decode_pem(contents)
      {:error, reason} -> {:error, {:file_read, reason, path}}
    end
  end

  # ----------------------------------------------------------- Certificates --

  def decode_certs(pem_string) when is_binary(pem_string) do
    with {:ok, entries} <- decode_pem(pem_string) do
      ders = for {:Certificate, der, :not_encrypted} <- entries, do: der

      case ders do
        [] -> {:error, :no_certificates_found}
        list -> {:ok, list}
      end
    end
  end

  def decode_certs_file(path) when is_binary(path) do
    with {:ok, contents} <- read_file(path) do
      decode_certs(contents)
    end
  end

  # ------------------------------------------------------------ Private keys --
  #
  # We accept whatever PEM the user supplies (traditional RSAPrivateKey /
  # ECPrivateKey or PKCS#8 PrivateKeyInfo, encrypted or not). The decoded
  # record from :public_key.pem_entry_decode/1 is wrapped with the original
  # PEM tag and the (decrypted) DER bytes so :ssl can be handed exactly the
  # form it expects.

  def decode_key(pem_string, password \\ nil) when is_binary(pem_string) do
    with {:ok, entries} <- decode_pem(pem_string) do
      case find_key_entry(entries) do
        nil -> {:error, :no_key_found}
        {_type, _der, :not_encrypted} = entry -> decode_unencrypted_key(entry)
        {_type, _der, _cipher} = entry -> decode_encrypted_key(entry, password)
      end
    end
  end

  def decode_key_file(path, password \\ nil) when is_binary(path) do
    with {:ok, contents} <- read_file(path) do
      decode_key(contents, password)
    end
  end

  @doc false
  def find_key_entry(entries) do
    Enum.find(entries, fn
      {:RSAPrivateKey, _, _} -> true
      {:ECPrivateKey, _, _} -> true
      {:DSAPrivateKey, _, _} -> true
      {:PrivateKeyInfo, _, _} -> true
      {:EncryptedPrivateKeyInfo, _, _} -> true
      _ -> false
    end)
  end

  defp decode_unencrypted_key({_type, _der, :not_encrypted} = entry) do
    record = :public_key.pem_entry_decode(entry)
    {:ok, build_key(entry, record)}
  rescue
    _ -> {:error, :invalid_key}
  end

  defp decode_encrypted_key(_entry, nil), do: {:error, :encrypted_key_no_password}

  defp decode_encrypted_key(entry, password) when is_binary(password) do
    trimmed = String.trim_trailing(password)

    case try_decode(entry, String.to_charlist(trimmed)) do
      {:ok, _} = ok ->
        ok

      {:error, _} when trimmed != password ->
        case try_decode(entry, String.to_charlist(password)) do
          {:ok, _} = ok -> ok
          {:error, _} -> {:error, :bad_password}
        end

      {:error, _} ->
        {:error, :bad_password}
    end
  end

  defp try_decode(entry, charlist_password) do
    record = :public_key.pem_entry_decode(entry, charlist_password)
    {:ok, build_key(entry, record)}
  rescue
    _ -> {:error, :decrypt_failed}
  end

  # The map we hand to the rest of Snippy. We always re-encode the record
  # so `:asn1_type` and `:der` are consistent: `pem_entry_decode/1` for
  # PKCS#8 unwraps the inner key (e.g. returns an `:RSAPrivateKey`
  # record), but the original PEM `:der` would still be PKCS#8 — passing
  # `{:RSAPrivateKey, <pkcs8-der>}` to `:ssl` then blows up at handshake
  # time. Re-encoding from the record gives the matching DER.
  defp build_key({pem_type, _der, :not_encrypted}, record) do
    asn1_type = record_tag(record)

    %{
      pem_type: pem_type,
      record: record,
      asn1_type: asn1_type,
      der: :public_key.der_encode(asn1_type, record)
    }
  end

  defp build_key({pem_type, _enc_der, _cipher}, record) do
    asn1_type = record_tag(record)

    %{
      pem_type: pem_type,
      record: record,
      asn1_type: asn1_type,
      der: :public_key.der_encode(asn1_type, record)
    }
  end

  defp record_tag(record) when is_tuple(record) and tuple_size(record) > 0,
    do: :erlang.element(1, record)

  # ------------------------------------------------- Key type classification --

  def key_type(%{record: record}), do: record_to_type(record)
  def key_type(_), do: :other

  @doc false
  def record_to_type({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}), do: :rsa
  def record_to_type({:ECPrivateKey, _, _, _, _}), do: :ecdsa
  def record_to_type({:ECPrivateKey, _, _, _, _, _}), do: :ecdsa
  def record_to_type({:DSAPrivateKey, _, _, _, _, _}), do: :dsa

  def record_to_type({:PrivateKeyInfo, _v, alg, _key, _attrs}) do
    case alg_oid(alg) do
      {1, 2, 840, 113_549, 1, 1, 1} -> :rsa
      {1, 2, 840, 10_045, 2, 1} -> :ecdsa
      {1, 3, 101, 112} -> :eddsa
      {1, 3, 101, 113} -> :eddsa
      _ -> :other
    end
  end

  def record_to_type(_), do: :other

  @doc false
  def alg_oid({:PrivateKeyInfo_privateKeyAlgorithm, oid, _}), do: oid
  def alg_oid({:AlgorithmIdentifier, oid, _}), do: oid
  def alg_oid({:PublicKeyAlgorithm, oid, _}), do: oid
  def alg_oid({:SignatureAlgorithm, oid, _}), do: oid

  @doc false
  def alg_params({:PrivateKeyInfo_privateKeyAlgorithm, _, p}), do: p
  def alg_params({:AlgorithmIdentifier, _, p}), do: p
  def alg_params({:PublicKeyAlgorithm, _, p}), do: p
  def alg_params({:SignatureAlgorithm, _, p}), do: p

  # --------------------------------------------------- Cert OTP destructuring --

  def decode_otp_cert(der) when is_binary(der) do
    :public_key.pkix_decode_cert(der, :otp)
  end

  defp tbs_of({:OTPCertificate, tbs, _sig_alg, _sig}), do: tbs

  defp validity_of(
         {:OTPTBSCertificate, _v, _serial, _sig, _issuer, validity, _subj, _spki, _iuid, _suid,
          _exts}
       ),
       do: validity

  defp subject_of(
         {:OTPTBSCertificate, _v, _serial, _sig, _issuer, _val, subject, _spki, _iuid, _suid,
          _exts}
       ),
       do: subject

  defp spki_of(
         {:OTPTBSCertificate, _v, _serial, _sig, _issuer, _val, _subj, spki, _iuid, _suid, _exts}
       ),
       do: spki

  defp extensions_of(
         {:OTPTBSCertificate, _v, _serial, _sig, _issuer, _val, _subj, _spki, _iuid, _suid, exts}
       ),
       do: exts

  # ---------------------------------------------------------- Cert validity --

  def cert_validity(der) when is_binary(der) do
    {:Validity, not_before, not_after} =
      der |> decode_otp_cert() |> tbs_of() |> validity_of()

    {parse_time(not_before), parse_time(not_after)}
  end

  def cert_valid_now?(der) when is_binary(der) do
    {nb, na} = cert_validity(der)
    now = DateTime.utc_now()
    DateTime.compare(now, nb) in [:gt, :eq] and DateTime.compare(now, na) in [:lt, :eq]
  end

  @doc false
  def parse_time({:utcTime, charlist}) do
    <<yy::binary-2, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2, "Z">> =
      List.to_string(charlist)

    yyyy =
      case String.to_integer(yy) do
        y when y >= 50 -> 1900 + y
        y -> 2000 + y
      end

    build_dt(yyyy, mm, dd, hh, mi, ss)
  end

  def parse_time({:generalTime, charlist}) do
    <<yyyy::binary-4, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2, "Z">> =
      List.to_string(charlist)

    build_dt(String.to_integer(yyyy), mm, dd, hh, mi, ss)
  end

  defp build_dt(yyyy, mm, dd, hh, mi, ss) do
    {:ok, naive} =
      NaiveDateTime.new(
        yyyy,
        String.to_integer(mm),
        String.to_integer(dd),
        String.to_integer(hh),
        String.to_integer(mi),
        String.to_integer(ss)
      )

    DateTime.from_naive!(naive, "Etc/UTC")
  end

  # ------------------------------------------------- Hostname (CN + SAN) ---

  def cert_hostnames(der) when is_binary(der) do
    tbs = der |> decode_otp_cert() |> tbs_of()
    cn = subject_cn(subject_of(tbs))
    sans = san_dns_names(extensions_of(tbs))

    sans
    |> Kernel.++(List.wrap(cn))
    |> Enum.map(&to_string/1)
    |> Enum.uniq()
  end

  @doc false
  def subject_cn({:rdnSequence, rdn_lists}) do
    Enum.find_value(rdn_lists, fn attrs ->
      Enum.find_value(attrs, fn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, value} -> string_value(value)
        _ -> nil
      end)
    end)
  end

  def subject_cn(_), do: nil

  @doc false
  def string_value({:utf8String, v}), do: v
  def string_value({:printableString, v}), do: List.to_string(v)
  def string_value({:ia5String, v}), do: List.to_string(v)
  def string_value(v) when is_list(v), do: List.to_string(v)
  def string_value(v) when is_binary(v), do: v
  def string_value(_), do: nil

  @doc false
  def san_dns_names(:asn1_NOVALUE), do: []
  def san_dns_names(nil), do: []

  def san_dns_names(extensions) when is_list(extensions) do
    Enum.find_value(extensions, [], fn
      {:Extension, {2, 5, 29, 17}, _critical, names} when is_list(names) ->
        for name <- names, dns = dns_name(name), dns != nil, do: dns

      _ ->
        nil
    end)
  end

  @doc false
  def dns_name({:dNSName, n}) when is_list(n), do: List.to_string(n)
  def dns_name({:dNSName, n}) when is_binary(n), do: n
  def dns_name(_), do: nil

  # --------------------------------------------------------- Fingerprints --

  def spki_fingerprint(cert_der) when is_binary(cert_der) do
    # Decode with :plain to get an asn1-encodable SubjectPublicKeyInfo record;
    # the :otp form is post-processed and not directly re-encodable.
    {:Certificate, tbs, _sig_alg, _sig} = :public_key.pkix_decode_cert(cert_der, :plain)
    spki = elem_plain_spki(tbs)
    der = :public_key.der_encode(:SubjectPublicKeyInfo, spki)
    :crypto.hash(:sha256, der)
  end

  defp elem_plain_spki(
         {:TBSCertificate, _v, _serial, _sig, _issuer, _val, _subj, spki, _iuid, _suid, _exts}
       ),
       do: spki

  def key_fingerprint(%{der: der}), do: :crypto.hash(:sha256, der)

  def fingerprint_hex(hash) when is_binary(hash) do
    hash
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map_join(":", &Enum.join/1)
  end

  # --------------------------------------------------- Cert/key match check --
  #
  # Sign a known plaintext with the private key and verify with the SPKI from
  # the cert. Works for any private key shape (PKCS#1, PKCS#8, EC, EdDSA).

  @match_message <<"snippy match probe", 0::32>>

  def cert_key_match?(cert_der, %{} = key) do
    cert_pub = cert_public_key(cert_der)
    {digest, signing_record} = digest_and_signer(key)
    sig = :public_key.sign(@match_message, digest, signing_record)
    :public_key.verify(@match_message, digest, sig, cert_pub)
  rescue
    _ -> false
  end

  @doc false
  def digest_and_signer(%{record: record} = key) do
    case key_type(key) do
      :eddsa -> {:none, record}
      _ -> {:sha256, signer_record(record)}
    end
  end

  # OTP's :public_key.sign/3 does not always accept a PKCS#8 PrivateKeyInfo
  # for RSA/EC; convert to traditional form when needed.
  @doc false
  def signer_record({:PrivateKeyInfo, _v, alg, octets, _attrs} = original) do
    case alg_oid(alg) do
      {1, 2, 840, 113_549, 1, 1, 1} -> :public_key.der_decode(:RSAPrivateKey, octets)
      {1, 2, 840, 10_045, 2, 1} -> :public_key.der_decode(:ECPrivateKey, octets)
      _ -> original
    end
  end

  def signer_record(other), do: other

  # Reconstruct a public-key value :public_key.verify/4 will accept.
  defp cert_public_key(cert_der) do
    spki = cert_der |> decode_otp_cert() |> tbs_of() |> spki_of()
    spki_to_public(spki)
  end

  @doc false
  def spki_to_public({:OTPSubjectPublicKeyInfo, _alg, {:RSAPublicKey, _, _} = rsa}), do: rsa

  def spki_to_public({:OTPSubjectPublicKeyInfo, alg, {:ECPoint, _} = point}) do
    {point, alg_params(alg)}
  end

  def spki_to_public({:OTPSubjectPublicKeyInfo, alg, point}) when is_binary(point) do
    {{:ECPoint, point}, alg_params(alg)}
  end

  def spki_to_public({:OTPSubjectPublicKeyInfo, alg, public}) do
    case alg_oid(alg) do
      {1, 3, 101, 112} -> {:ed_pub, :ed25519, public}
      {1, 3, 101, 113} -> {:ed_pub, :ed448, public}
      _ -> public
    end
  end

  # ------------------------------------------------------- Chain validation --

  @doc """
  Validate `leaf_der` against a list of CA DERs.

  We pick the last CA in the list as the trust anchor (root). Any
  intermediates appear before it in `ca_ders`, ordered from leaf side toward
  root.
  """
  def validate_chain(_leaf_der, []), do: {:error, :no_ca}

  def validate_chain(leaf_der, ca_ders) when is_list(ca_ders) do
    {trust_anchor_der, intermediates} = List.pop_at(ca_ders, -1)
    chain = intermediates ++ [leaf_der]

    case :public_key.pkix_path_validation(trust_anchor_der, chain, []) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, {:validation_exception, Exception.message(e)}}
  end

  def validate_against_castore(leaf_der, intermediates \\ []) do
    if Code.ensure_loaded?(CAStore) and function_exported?(CAStore, :file_path, 0) do
      validate_with_castore(leaf_der, intermediates)
    else
      {:error, :castore_not_available}
    end
  end

  defp validate_with_castore(leaf_der, intermediates) do
    with {:ok, pem} <- File.read(CAStore.file_path()),
         {:ok, ca_entries} <- decode_pem(pem) do
      ca_ders = for {:Certificate, der, :not_encrypted} <- ca_entries, do: der
      try_each_root(leaf_der, intermediates, ca_ders)
    else
      {:error, reason} -> {:error, {:castore, reason}}
    end
  end

  @doc false
  def try_each_root(leaf_der, intermediates, ca_ders) do
    chain = intermediates ++ [leaf_der]

    Enum.reduce_while(ca_ders, {:error, :no_match}, fn root_der, _acc ->
      try do
        case :public_key.pkix_path_validation(root_der, chain, []) do
          {:ok, _} -> {:halt, :ok}
          {:error, _} -> {:cont, {:error, :no_match}}
        end
      rescue
        _ -> {:cont, {:error, :no_match}}
      end
    end)
  end

  # ------------------------------------------------------------- Helpers ---

  defp read_file(path) do
    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, {:file_read, reason, path}}
    end
  end
end
