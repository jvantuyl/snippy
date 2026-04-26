defmodule Snippy.Discovery do
  @moduledoc false

  require Logger
  alias Snippy.Decoder

  defmodule Group do
    @moduledoc false
    defstruct [
      :prefix,
      :key,
      :hostnames,
      :has_password?,
      :has_ca_chain?,
      :cert_source,
      :key_source,
      :ocsp_stapling?,
      :spki_fingerprint,
      :key_fingerprint,
      :key_type,
      :not_before,
      :not_after,
      :chain_validation,
      :chain_validation_reason
    ]
  end

  defstruct id: nil,
            table: :snippy_certs,
            default_hostname: nil,
            reload_interval_ms: nil,
            groups: []

  # Suffix table: maps suffix -> {slot, kind}
  # slot: :cert | :key | :password | :ca | :ocsp_stapling | :ocsp_stapling_typo
  # kind: :inline | :file | :flag

  @suffixes [
    {"_CRT", :cert, :inline},
    {"_CRT_FILE", :cert, :file},
    {"_KEY", :key, :inline},
    {"_KEY_FILE", :key, :file},
    {"_PWD", :password, :inline},
    {"_PWD_FILE", :password, :file},
    {"_PASS", :password, :inline},
    {"_PASS_FILE", :password, :file},
    {"_PASSWD", :password, :inline},
    {"_PASSWD_FILE", :password, :file},
    {"_PASSWORD", :password, :inline},
    {"_PASSWORD_FILE", :password, :file},
    {"_CACRT", :ca, :inline},
    {"_CACRT_FILE", :ca, :file},
    {"_OCSP_STAPLING", :ocsp_stapling, :flag},
    {"_OSCP_STAPLING", :ocsp_stapling_typo, :flag}
  ]

  # Sorted longest-first so longer suffixes win in greedy matching
  @suffixes_sorted Enum.sort_by(@suffixes, fn {s, _, _} -> -byte_size(s) end)

  def suffixes, do: @suffixes_sorted

  @doc """
  Run discovery against an env map (or System.get_env/0 if not given).

  Returns a list of group records (success only). Drops groups whose
  validation fails, logging an error.
  """
  def discover(opts) do
    env = opts[:env] || System.get_env()
    case_sensitive = Keyword.get(opts, :case_sensitive, true)
    prefixes = normalize_prefixes!(opts[:prefix])
    expiry_grace = Keyword.get(opts, :expiry_grace_seconds, 0)
    public_ca = Keyword.get(opts, :public_ca_validation, :auto)

    if public_ca == :always and not castore_available?() do
      raise ArgumentError,
            "public_ca_validation: :always requires the :castore dependency"
    end

    raw_matches = scan_env(env, prefixes, case_sensitive)
    Logger.debug("snippy: scanned #{map_size(env)} env vars, matched #{length(raw_matches)}")

    grouped = group_matches(raw_matches)

    grouped
    |> Enum.map(&materialize_group/1)
    |> Enum.map(&validate_group(&1, expiry_grace, public_ca))
    |> Enum.reject(&is_nil/1)
  end

  defp castore_available? do
    Code.ensure_loaded?(CAStore) and function_exported?(CAStore, :file_path, 0)
  end

  # --- Prefix normalization ---

  def normalize_prefixes!(nil) do
    raise ArgumentError, "Snippy: :prefix option is required"
  end

  def normalize_prefixes!(prefix) when is_list(prefix) do
    prefix
    |> Enum.map(&normalize_prefix!/1)
    |> Enum.uniq()
    |> validate_no_overlap!()
  end

  def normalize_prefixes!(prefix) do
    [normalize_prefix!(prefix)]
  end

  defp normalize_prefix!(:elixir),
    do: raise(ArgumentError, "Snippy: :elixir is not a valid prefix")

  defp normalize_prefix!(nil),
    do: raise(ArgumentError, "Snippy: nil is not a valid prefix")

  defp normalize_prefix!(true),
    do: raise(ArgumentError, "Snippy: true is not a valid prefix")

  defp normalize_prefix!(false),
    do: raise(ArgumentError, "Snippy: false is not a valid prefix")

  defp normalize_prefix!(p) when is_atom(p) do
    p |> Atom.to_string() |> String.upcase()
  end

  defp normalize_prefix!("") do
    ""
  end

  defp normalize_prefix!(p) when is_binary(p) do
    String.upcase(p)
  end

  defp normalize_prefix!(other) do
    raise ArgumentError, "Snippy: invalid prefix #{inspect(other)}"
  end

  defp validate_no_overlap!(prefixes) do
    for a <- prefixes, b <- prefixes, a != b do
      if a != "" and b != "" and String.starts_with?(b, a <> "_") do
        raise ArgumentError,
              "Snippy: ambiguous prefixes: #{inspect(a)} is a prefix of #{inspect(b)}"
      end
    end

    prefixes
  end

  # --- Scanning ---

  defp scan_env(env, prefixes, case_sensitive) do
    Enum.flat_map(env, fn {var, val} ->
      case match_var(var, prefixes, case_sensitive) do
        {:ok, prefix, key, suffix, slot, kind} ->
          Logger.debug(
            "snippy: matched #{var} -> prefix=#{inspect(prefix)} key=#{key} suffix=#{suffix}"
          )

          [{prefix, key, suffix, slot, kind, var, val}]

        :no_match ->
          []
      end
    end)
  end

  defp match_var(var, prefixes, case_sensitive) do
    var_search = if case_sensitive, do: var, else: String.upcase(var)

    Enum.find_value(prefixes, :no_match, fn prefix ->
      prefix_search = if case_sensitive, do: prefix, else: prefix

      candidate =
        cond do
          prefix == "" ->
            var_search

          String.starts_with?(var_search, prefix_search <> "_") ->
            binary_part(
              var_search,
              byte_size(prefix_search) + 1,
              byte_size(var_search) - byte_size(prefix_search) - 1
            )

          true ->
            nil
        end

      if candidate do
        match_suffix(candidate, prefix)
      else
        nil
      end
    end)
  end

  defp match_suffix(candidate, prefix) do
    Enum.find_value(@suffixes_sorted, fn {suffix, slot, kind} ->
      if String.ends_with?(candidate, suffix) and byte_size(candidate) > byte_size(suffix) do
        key = binary_part(candidate, 0, byte_size(candidate) - byte_size(suffix))
        # Trim leading underscore from key if present (when prefix was empty)
        key = String.trim_leading(key, "_")

        if key == "" do
          nil
        else
          {:ok, prefix, key, suffix, slot, kind}
        end
      end
    end)
  end

  # --- Grouping ---

  defp group_matches(matches) do
    matches
    |> Enum.group_by(fn {prefix, key, _suffix, _slot, _kind, _var, _val} -> {prefix, key} end)
    |> Enum.map(fn {{prefix, key}, entries} ->
      group = build_group_map(prefix, key, entries)
      group
    end)
  end

  defp build_group_map(prefix, key, entries) do
    {ocsp, typo_warned?} = extract_ocsp(entries)

    password = extract_password!(entries, prefix, key)

    cert =
      Enum.find(entries, fn {_p, _k, _s, slot, _kind, _v, _val} -> slot == :cert end)

    key_var =
      Enum.find(entries, fn {_p, _k, _s, slot, _kind, _v, _val} -> slot == :key end)

    ca =
      Enum.find(entries, fn {_p, _k, _s, slot, _kind, _v, _val} -> slot == :ca end)

    %{
      prefix: prefix,
      key: key,
      cert: cert,
      key_var: key_var,
      password: password,
      ca: ca,
      ocsp: ocsp,
      typo_warned?: typo_warned?
    }
  end

  defp extract_ocsp(entries) do
    canonical =
      Enum.find(entries, fn {_p, _k, _s, slot, _kind, _v, _val} ->
        slot == :ocsp_stapling
      end)

    typo =
      Enum.find(entries, fn {_p, _k, _s, slot, _kind, _v, _val} ->
        slot == :ocsp_stapling_typo
      end)

    typo_warned? =
      cond do
        typo && canonical ->
          {_, _, _, _, _, var, _} = typo
          Logger.warning("snippy: #{var} is a misspelling of _OCSP_STAPLING; using canonical")
          true

        typo ->
          {_, _, _, _, _, var, _} = typo
          Logger.warning("snippy: #{var} is a misspelling of _OCSP_STAPLING; honoring it anyway")
          true

        true ->
          false
      end

    chosen = canonical || typo

    flag =
      case chosen do
        nil -> false
        {_p, _k, _s, _slot, _kind, _v, val} -> parse_bool!(val)
      end

    {flag, typo_warned?}
  end

  defp parse_bool!(val) when is_binary(val) do
    case String.downcase(String.trim(val)) do
      v when v in ["true", "on", "enabled", "enable", "1"] -> true
      v when v in ["false", "off", "disabled", "disable", "0"] -> false
      other -> raise ArgumentError, "Snippy: invalid boolean value #{inspect(other)}"
    end
  end

  defp extract_password!(entries, prefix, key) do
    pw_entries =
      Enum.filter(entries, fn {_p, _k, _s, slot, _kind, _v, _val} -> slot == :password end)

    case pw_entries do
      [] ->
        nil

      [single] ->
        single

      multiple ->
        names = Enum.map(multiple, fn {_p, _k, _s, _slot, _kind, var, _val} -> var end)

        raise ArgumentError,
              "Snippy: multiple password variables for prefix=#{inspect(prefix)} key=#{key}: #{Enum.join(names, ", ")}"
    end
  end

  # --- Materialization ---

  defp materialize_group(%{cert: nil, key_var: nil} = g) do
    Logger.debug("snippy: skipping #{inspect(g.prefix)}/#{g.key}: no cert or key")
    nil
  end

  defp materialize_group(%{cert: nil} = g) do
    Logger.error(
      "snippy: #{inspect(g.prefix)}/#{g.key}: key present but no certificate; dropping"
    )

    nil
  end

  defp materialize_group(%{key_var: nil} = g) do
    Logger.error(
      "snippy: #{inspect(g.prefix)}/#{g.key}: certificate present but no key; dropping"
    )

    nil
  end

  defp materialize_group(g) do
    {_, _, _, _, cert_kind, cert_var, cert_val} = g.cert
    {_, _, _, _, key_kind, key_var, key_val} = g.key_var

    password_str =
      case g.password do
        nil ->
          nil

        {_, _, _, _, :inline, _var, val} ->
          val

        {_, _, _, _, :file, var, path} ->
          Logger.warning("snippy: #{var} loads password from file (#{path})")

          case File.read(path) do
            {:ok, contents} -> contents
            {:error, reason} -> {:error, {:password_file, reason, path}}
          end
      end

    case password_str do
      {:error, _reason} = err ->
        Logger.error(
          "snippy: #{inspect(g.prefix)}/#{g.key}: cannot read password file: #{inspect(err)}"
        )

        nil

      _ ->
        Map.merge(g, %{
          cert_kind: cert_kind,
          cert_var: cert_var,
          cert_val: cert_val,
          key_kind: key_kind,
          key_var_name: key_var,
          key_val: key_val,
          password_str: password_str
        })
    end
  end

  # --- Validation ---

  defp validate_group(nil, _grace, _public_ca), do: nil

  defp validate_group(g, grace, public_ca) do
    label = "#{inspect(g.prefix)}/#{g.key}"

    with {:ok, cert_ders} <- load_cert_chain(g),
         {:ok, key} <- load_key(g),
         :ok <- check_match(cert_ders, key, label),
         :ok <- check_validity(cert_ders, label, grace),
         {:ok, ca_ders} <- load_ca_chain(g),
         {chain_status, chain_reason} <-
           validate_chain_or_castore(hd(cert_ders), ca_ders, public_ca, label) do
      build_group_struct(g, cert_ders, key, ca_ders, chain_status, chain_reason)
    else
      {:error, reason} ->
        Logger.error("snippy: #{label}: #{format_error(reason)}; dropping")
        nil
    end
  end

  defp load_cert_chain(%{cert_kind: :inline, cert_val: pem}) do
    Decoder.decode_certs(pem)
  end

  defp load_cert_chain(%{cert_kind: :file, cert_val: path}) do
    Decoder.decode_certs_file(path)
  end

  defp load_key(%{key_kind: :inline, key_val: pem, password_str: password}) do
    Decoder.decode_key(pem, password)
  end

  defp load_key(%{key_kind: :file, key_val: path, password_str: password}) do
    if path |> File.read!() |> String.contains?("ENCRYPTED") and password == nil do
      Logger.warning("snippy: encrypted key file #{path} but no password set; will likely fail")
    end

    Decoder.decode_key_file(path, password)
  rescue
    e in File.Error ->
      {:error, {:file_read, e.reason, path}}
  end

  defp check_match([leaf | _], key, label) do
    if Decoder.cert_key_match?(leaf, key) do
      :ok
    else
      Logger.error("snippy: #{label}: cert/key mismatch")
      {:error, :cert_key_mismatch}
    end
  end

  defp check_validity([leaf | _], label, grace) do
    {not_before, not_after} = Decoder.cert_validity(leaf)
    now = DateTime.utc_now()
    grace_dt_after = DateTime.add(not_after, grace, :second)

    cond do
      DateTime.compare(now, not_before) == :lt ->
        Logger.error("snippy: #{label}: not yet valid until #{not_before}")
        {:error, {:not_yet_valid, not_before}}

      DateTime.compare(now, grace_dt_after) == :gt ->
        Logger.error("snippy: #{label}: expired at #{not_after}")
        {:error, {:expired, not_after}}

      true ->
        :ok
    end
  end

  defp load_ca_chain(%{ca: nil}), do: {:ok, []}

  defp load_ca_chain(%{ca: {_, _, _, _, :inline, _var, pem}}) do
    Decoder.decode_certs(pem)
  end

  defp load_ca_chain(%{ca: {_, _, _, _, :file, _var, path}}) do
    Decoder.decode_certs_file(path)
  end

  # `intermediates` are CA certs we discovered ourselves (`_CACRT*`); they
  # never include the leaf. `Decoder.validate_chain` expects the same shape.
  defp validate_chain_or_castore(leaf, intermediates, public_ca, label) do
    cond do
      intermediates != [] ->
        case Decoder.validate_chain(leaf, intermediates) do
          :ok ->
            {:ok_chain, nil}

          {:error, reason} ->
            Logger.warning(
              "snippy: #{label}: chain validation against provided CA failed: #{inspect(reason)}"
            )

            try_public_ca(leaf, intermediates, public_ca, label)
        end

      true ->
        try_public_ca(leaf, intermediates, public_ca, label)
    end
  end

  defp try_public_ca(leaf, intermediates, mode, label) do
    cond do
      mode == :never ->
        log_self_signed(label)
        {:ok_self, nil}

      castore_available?() ->
        case Decoder.validate_against_castore(leaf, intermediates) do
          :ok ->
            Logger.info("snippy: #{label}: validated against public CA bundle")
            {:ok_public, nil}

          {:error, reason} ->
            if mode == :always do
              Logger.error("snippy: #{label}: public CA validation failed: #{inspect(reason)}")
              {:error_chain, reason}
            else
              Logger.warning(
                "snippy: #{label}: public CA validation failed: #{inspect(reason)}; accepting"
              )

              log_self_signed(label)
              {:ok_self, reason}
            end
        end

      true ->
        log_self_signed(label)
        {:ok_self, nil}
    end
  end

  defp log_self_signed(label) do
    Logger.info("snippy: #{label}: no chain validation; trusting cert as-is")
  end

  defp build_group_struct(g, cert_ders, key, ca_ders, chain_status, chain_reason) do
    if chain_status == :error_chain do
      nil
    else
      [leaf | _] = cert_ders
      {not_before, not_after} = Decoder.cert_validity(leaf)
      hostnames = Decoder.cert_hostnames(leaf)

      %Group{
        prefix: g.prefix,
        key: g.key,
        hostnames: hostnames,
        has_password?: g.password != nil,
        has_ca_chain?: ca_ders != [],
        cert_source: g.cert_kind,
        key_source: g.key_kind,
        ocsp_stapling?: g.ocsp,
        spki_fingerprint: Decoder.spki_fingerprint(leaf),
        key_fingerprint: Decoder.key_fingerprint(key),
        key_type: Decoder.key_type(key),
        not_before: not_before,
        not_after: not_after,
        chain_validation: chain_status,
        chain_validation_reason: chain_reason
      }
      |> with_ssl_payload(cert_ders, key, ca_ders, g)
    end
  end

  # Stash the payload used to build :ssl options on the struct via a private
  # field carried in process dict-free form by attaching as a separate element
  # in ETS. We return both pieces from the caller via {:group, struct, payload}.
  # For now, attach to a private map under :__ssl_payload__.
  defp with_ssl_payload(struct, cert_ders, key, ca_ders, g) do
    payload = build_ssl_payload(cert_ders, key, ca_ders, g)
    Map.put(struct, :__ssl_payload__, payload)
  end

  defp build_ssl_payload(cert_ders, key, ca_ders, g) do
    full_chain = cert_ders ++ ca_ders

    base =
      cond do
        g.cert_kind == :file and ca_ders == [] ->
          %{certfile: g.cert_val}

        true ->
          %{cert: full_chain}
      end

    base =
      cond do
        g.key_kind == :file and ca_ders == [] ->
          Map.put(base, :keyfile, g.key_val)

        true ->
          Map.put(base, :key, ssl_key_form(key))
      end

    case g.password_str do
      nil -> base
      pw -> Map.put(base, :password, pw)
    end
  end

  defp ssl_key_form(%{asn1_type: type, der: der}) do
    {type, der}
  end

  defp format_error({:file_read, reason, path}), do: "cannot read #{path}: #{inspect(reason)}"
  defp format_error(:invalid_pem), do: "invalid PEM"
  defp format_error(:no_certificates_found), do: "no certificates found"
  defp format_error(:no_key_found), do: "no private key found"
  defp format_error(:bad_password), do: "wrong password (or unable to decrypt)"
  defp format_error(:encrypted_key_no_password), do: "key is encrypted but no password set"
  defp format_error(:cert_key_mismatch), do: "cert public key does not match private key"
  defp format_error({:not_yet_valid, t}), do: "not yet valid (notBefore=#{t})"
  defp format_error({:expired, t}), do: "expired (notAfter=#{t})"
  defp format_error(other), do: inspect(other)
end
