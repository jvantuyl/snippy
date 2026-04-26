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
      :spki_fingerprint,
      :key_fingerprint,
      :key_type,
      :not_before,
      :not_after,
      :chain_validation,
      :chain_validation_reason,
      # Internal: the :ssl `:certs_keys` map for this group. Populated when
      # the group is materialized; nil on stripped public-handle groups
      # returned from `Snippy.discover_certificates/1`.
      :ssl_payload
    ]
  end

  defstruct id: nil,
            table: :snippy_certs,
            default_hostname: nil,
            reload_interval_ms: nil,
            groups: [],
            errors: []

  # Suffix table: maps suffix -> {slot, kind}
  # slot: :cert | :key | :password | :ca
  # kind: :inline | :file

  @suffixes [
    {"_CRT", :cert, :inline},
    {"_CRT_FILE", :cert, :file},
    {"_CERT", :cert, :inline},
    {"_CERT_FILE", :cert, :file},
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
    {"_CACERT", :ca, :inline},
    {"_CACERT_FILE", :ca, :file}
  ]

  # Sorted longest-first so longer suffixes win in greedy matching
  @suffixes_sorted Enum.sort_by(@suffixes, fn {s, _, _} -> -byte_size(s) end)

  def suffixes, do: @suffixes_sorted

  # ----------------------------------------------------------- Phase 1: scan

  @doc """
  Cheap, broad env scan.

  Walks the environment and emits one entry per env var whose name ends in
  one of our recognized suffixes. **Does not** decode PEM, read cert/key
  files, or validate anything. The full var name is preserved so later
  phases can split off whatever prefix the caller is interested in.

  Options:
    * `:env` - env map override (default: `System.get_env/0`)
    * `:case_sensitive` - default `true`. When `false`, suffix matching is
      case-insensitive (we always upcase the recognition surface).

  Returns a list of maps:

      %{var: "MYAPP_API_CRT_FILE", suffix: "_CRT_FILE", slot: :cert,
        kind: :file, val: "/run/secrets/api.crt.pem"}
  """
  def scan_all(opts \\ []) do
    env = opts[:env] || System.get_env()
    case_sensitive = Keyword.get(opts, :case_sensitive, true)

    Enum.flat_map(env, fn {var, val} ->
      candidate = if case_sensitive, do: var, else: String.upcase(var)

      case match_suffix_only(candidate) do
        {:ok, suffix, slot, kind} ->
          [%{var: var, suffix: suffix, slot: slot, kind: kind, val: val}]

        :no_match ->
          []
      end
    end)
  end

  defp match_suffix_only(var) do
    Enum.find_value(@suffixes_sorted, :no_match, fn {suffix, slot, kind} ->
      if String.ends_with?(var, suffix) and byte_size(var) > byte_size(suffix) do
        {:ok, suffix, slot, kind}
      end
    end)
  end

  # ------------------------------------- Phase 1.5: filter scan by prefix(es)

  @doc """
  Given the output of `scan_all/1` and a list of normalized (uppercased)
  prefixes, return entries whose var name starts with `<prefix>_` and whose
  remainder (after stripping the prefix and the trailing suffix) is non-empty.

  Each output entry adds `:prefix` and `:key` (both uppercase) to the input
  shape.
  """
  def filter_by_prefixes(entries, prefixes, case_sensitive \\ true) do
    Enum.flat_map(entries, fn entry ->
      var_search = if case_sensitive, do: entry.var, else: String.upcase(entry.var)

      Enum.find_value(prefixes, [], fn prefix ->
        peel_prefix(entry, var_search, prefix)
      end)
      |> List.wrap()
    end)
  end

  defp peel_prefix(entry, var_search, prefix) do
    suffix = entry.suffix

    cond do
      prefix == "" ->
        peel_no_prefix(entry, var_search, suffix)

      String.starts_with?(var_search, prefix <> "_") and
          String.ends_with?(var_search, suffix) ->
        peel_with_prefix(entry, var_search, prefix, suffix)

      true ->
        nil
    end
  end

  defp peel_no_prefix(entry, var_search, suffix) do
    body_len = byte_size(var_search) - byte_size(suffix)

    with true <- body_len > 0,
         key = binary_part(var_search, 0, body_len) |> String.trim_leading("_"),
         true <- key != "" do
      Map.merge(entry, %{prefix: "", key: key})
    else
      _ -> nil
    end
  end

  defp peel_with_prefix(entry, var_search, prefix, suffix) do
    body_start = byte_size(prefix) + 1
    body_len = byte_size(var_search) - body_start - byte_size(suffix)

    with true <- body_len > 0,
         key = binary_part(var_search, body_start, body_len),
         true <- key != "" do
      Map.merge(entry, %{prefix: prefix, key: key})
    else
      _ -> nil
    end
  end

  # --------------------------------------------------------- Phase 2: groups

  @doc """
  Given a list of prefix-tagged entries (from `filter_by_prefixes/3`),
  group them by `{prefix, key}` and return a list of raw group maps suitable
  for `materialize_group/2`.
  """
  def group_entries(entries) do
    entries
    |> Enum.group_by(fn e -> {e.prefix, e.key} end)
    |> Enum.map(fn {{prefix, key}, group_entries} ->
      build_raw_group(prefix, key, group_entries)
    end)
  end

  defp build_raw_group(prefix, key, entries) do
    password = extract_password!(entries, prefix, key)
    cert = Enum.find(entries, &(&1.slot == :cert))
    key_var = Enum.find(entries, &(&1.slot == :key))
    ca = Enum.find(entries, &(&1.slot == :ca))

    %{
      prefix: prefix,
      key: key,
      cert: cert,
      key_var: key_var,
      password: password,
      ca: ca
    }
  end

  defp extract_password!(entries, prefix, key) do
    pw_entries = Enum.filter(entries, &(&1.slot == :password))

    case pw_entries do
      [] ->
        nil

      [single] ->
        single

      multiple ->
        names = Enum.map(multiple, & &1.var)

        raise ArgumentError,
              "Snippy: multiple password variables for prefix=#{inspect(prefix)} key=#{key}: #{Enum.join(names, ", ")}"
    end
  end

  # ------------------------------- Phase 3: materialize ONE group on demand

  @doc """
  Given a raw group (as built by `group_entries/1`) and validation opts,
  produce either `{:ok, %Group{}}` (the struct includes a private
  `:__ssl_payload__` map for use by lookup) or `{:error, reason}`.

  Reads files, decodes PEM, validates, builds the SSL payload. This is the
  expensive phase; it must only run for groups whose `(prefix, key)` an
  actual helper is asking about.

  Options:
    * `:expiry_grace_seconds` - default 0
    * `:public_ca_validation` - `:auto | :always | :never`, default `:auto`
  """
  def materialize_group(raw_group, opts \\ []) do
    grace = Keyword.get(opts, :expiry_grace_seconds, 0)
    public_ca = Keyword.get(opts, :public_ca_validation, :auto)

    if public_ca == :always and not castore_available?() do
      {:error, :castore_required_for_always_validation}
    else
      with {:ok, prepared} <- materialize_prepare(raw_group) do
        validate_group(prepared, grace, public_ca)
      end
    end
  end

  # ---------------------------------------------------- normalize prefixes

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

  defp castore_available? do
    Code.ensure_loaded?(CAStore) and function_exported?(CAStore, :file_path, 0)
  end

  # ----------------------------------------------------- Materialization ---

  defp materialize_prepare(%{cert: nil, key_var: nil}) do
    {:error, :no_cert_or_key}
  end

  defp materialize_prepare(%{cert: nil}) do
    {:error, :key_without_cert}
  end

  defp materialize_prepare(%{key_var: nil}) do
    {:error, :cert_without_key}
  end

  defp materialize_prepare(g) do
    case resolve_password(g.password) do
      {:ok, password_str} ->
        cert = g.cert
        key_var = g.key_var

        prepared =
          Map.merge(g, %{
            cert_kind: cert.kind,
            cert_var: cert.var,
            cert_val: cert.val,
            key_kind: key_var.kind,
            key_var_name: key_var.var,
            key_val: key_var.val,
            password_str: password_str
          })

        {:ok, prepared}

      {:error, _} = err ->
        err
    end
  end

  defp resolve_password(nil), do: {:ok, nil}

  defp resolve_password(%{kind: :inline, val: val}), do: {:ok, val}

  defp resolve_password(%{kind: :file, var: var, val: path}) do
    Logger.warning("snippy: #{var} loads password from file (#{path})")

    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, {:password_file, reason, path}}
    end
  end

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

  defp check_match([leaf | _], key, _label) do
    if Decoder.cert_key_match?(leaf, key) do
      :ok
    else
      {:error, :cert_key_mismatch}
    end
  end

  defp check_validity([leaf | _], _label, grace) do
    {not_before, not_after} = Decoder.cert_validity(leaf)
    now = DateTime.utc_now()
    grace_dt_after = DateTime.add(not_after, grace, :second)

    cond do
      DateTime.compare(now, not_before) == :lt ->
        {:error, {:not_yet_valid, not_before}}

      DateTime.compare(now, grace_dt_after) == :gt ->
        {:error, {:expired, not_after}}

      true ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  defp load_ca_chain(%{ca: nil}), do: {:ok, []}

  defp load_ca_chain(%{ca: %{kind: :inline, val: pem}}) do
    Decoder.decode_certs(pem)
  end

  defp load_ca_chain(%{ca: %{kind: :file, val: path}}) do
    Decoder.decode_certs_file(path)
  end

  defp validate_chain_or_castore(leaf, [], public_ca, label) do
    try_public_ca(leaf, [], public_ca, label)
  end

  defp validate_chain_or_castore(leaf, intermediates, public_ca, label) do
    case Decoder.validate_chain(leaf, intermediates) do
      :ok ->
        {:ok_chain, nil}

      {:error, reason} ->
        Logger.warning(
          "snippy: #{label}: chain validation against provided CA failed: #{inspect(reason)}"
        )

        try_public_ca(leaf, intermediates, public_ca, label)
    end
  end

  defp try_public_ca(leaf, intermediates, mode, label) do
    cond do
      mode == :never ->
        log_self_signed(label)
        {:ok_self, nil}

      castore_available?() ->
        validate_against_castore(leaf, intermediates, mode, label)

      true ->
        log_self_signed(label)
        {:ok_self, nil}
    end
  end

  defp validate_against_castore(leaf, intermediates, mode, label) do
    case Decoder.validate_against_castore(leaf, intermediates) do
      :ok ->
        Logger.info("snippy: #{label}: validated against public CA bundle")
        {:ok_public, nil}

      {:error, reason} when mode == :always ->
        {:error_chain, reason}

      {:error, reason} ->
        Logger.warning(
          "snippy: #{label}: public CA validation failed: #{inspect(reason)}; accepting"
        )

        log_self_signed(label)
        {:ok_self, reason}
    end
  end

  defp log_self_signed(label) do
    Logger.info("snippy: #{label}: no chain validation; trusting cert as-is")
  end

  defp build_group_struct(g, cert_ders, key, ca_ders, :error_chain, reason) do
    _ = g
    _ = cert_ders
    _ = key
    _ = ca_ders
    {:error, {:public_ca_required, reason}}
  end

  defp build_group_struct(g, cert_ders, key, ca_ders, chain_status, chain_reason) do
    [leaf | _] = cert_ders
    {not_before, not_after} = Decoder.cert_validity(leaf)
    hostnames = Decoder.cert_hostnames(leaf)
    payload = build_ssl_payload(cert_ders, key, ca_ders, g)

    group =
      struct!(Group,
        prefix: g.prefix,
        key: g.key,
        hostnames: hostnames,
        has_password?: g.password != nil,
        has_ca_chain?: ca_ders != [],
        cert_source: g.cert_kind,
        key_source: g.key_kind,
        spki_fingerprint: Decoder.spki_fingerprint(leaf),
        key_fingerprint: Decoder.key_fingerprint(key),
        key_type: Decoder.key_type(key),
        not_before: not_before,
        not_after: not_after,
        chain_validation: chain_status,
        chain_validation_reason: chain_reason,
        ssl_payload: payload
      )

    {:ok, group}
  end

  defp build_ssl_payload(cert_ders, key, ca_ders, g) do
    full_chain = cert_ders ++ ca_ders

    base =
      if g.cert_kind == :file and ca_ders == [] do
        %{certfile: g.cert_val}
      else
        %{cert: full_chain}
      end

    base =
      if g.key_kind == :file and ca_ders == [] do
        Map.put(base, :keyfile, g.key_val)
      else
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

  @doc """
  Format a materialization error reason as a human-readable string for logs.
  """
  def format_error({:file_read, reason, path}), do: "cannot read #{path}: #{inspect(reason)}"

  def format_error({:password_file, reason, path}),
    do: "cannot read password file #{path}: #{inspect(reason)}"

  def format_error(:invalid_pem), do: "invalid PEM"
  def format_error(:no_certificates_found), do: "no certificates found"
  def format_error(:no_key_found), do: "no private key found"
  def format_error(:bad_password), do: "wrong password (or unable to decrypt)"
  def format_error(:encrypted_key_no_password), do: "key is encrypted but no password set"
  def format_error(:cert_key_mismatch), do: "cert public key does not match private key"
  def format_error(:no_cert_or_key), do: "no cert or key found for group"
  def format_error(:key_without_cert), do: "key present but no certificate"
  def format_error(:cert_without_key), do: "certificate present but no key"

  def format_error(:castore_required_for_always_validation),
    do: "public_ca_validation: :always requires the :castore dependency"

  def format_error({:not_yet_valid, t}), do: "not yet valid (notBefore=#{t})"
  def format_error({:expired, t}), do: "expired (notAfter=#{t})"

  def format_error({:public_ca_required, reason}),
    do: "public CA validation required and failed: #{inspect(reason)}"

  def format_error(other), do: inspect(other)
end
