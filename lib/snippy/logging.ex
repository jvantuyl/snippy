defmodule Snippy.Logging do
  @moduledoc false

  require Logger

  alias Snippy.Decoder
  alias Snippy.Discovery.Group

  @table Snippy.TableOwner.table_name()

  @doc """
  Resolve the effective log level from opts and application env.

  Returns a Logger level atom or `false` to disable.
  """
  def level(opts) do
    case Keyword.get(opts, :log_level) do
      nil -> Application.get_env(:snippy, :log_level, :debug)
      :none -> false
      false -> false
      level -> level
    end
  end

  @doc """
  Log discovery results if the level is enabled and groups have changed.
  """
  def log_discovery(groups, prefixes, opts) do
    case level(opts) do
      false -> :ok
      level -> maybe_log(groups, prefixes, level)
    end
  end

  defp maybe_log(groups, prefixes, level) do
    fp = fingerprint(groups)
    prefixes_sorted = Enum.sort(prefixes)
    cache_key = {fp, prefixes_sorted}

    if suppressed?(cache_key) do
      :ok
    else
      emit(groups, prefixes, level)
      store_fingerprint(cache_key)
    end
  end

  defp suppressed?(cache_key) do
    case :ets.whereis(@table) do
      :undefined ->
        false

      _tid ->
        case :ets.lookup(@table, :last_logged_fingerprint) do
          [{_, ^cache_key}] -> true
          _ -> false
        end
    end
  end

  defp store_fingerprint(cache_key) do
    case :ets.whereis(@table) do
      :undefined -> :ok
      _tid -> :ets.insert(@table, {:last_logged_fingerprint, cache_key})
    end
  end

  defp emit(groups, prefixes, level) do
    announcement = announcement_line(groups, prefixes)
    Logger.log(level, announcement)

    Enum.each(groups, fn g ->
      Logger.log(level, group_line(g))
    end)
  end

  defp announcement_line(groups, []) do
    "snippy: building config from supplied discovery -> #{group_count(groups)}"
  end

  defp announcement_line(groups, prefixes) do
    "snippy: discovering certificates for prefix(es) #{inspect(prefixes)} -> #{group_count(groups)}"
  end

  defp group_count([]), do: "no groups"
  defp group_count(groups), do: "#{length(groups)} group(s)"

  defp group_line(%Group{} = g) do
    hosts = Enum.join(g.hostnames, ",")
    spki = if g.spki_fingerprint, do: Decoder.fingerprint_hex(g.spki_fingerprint), else: "n/a"
    ca = if g.has_ca_chain?, do: "present", else: "absent"
    pwd = if g.has_password?, do: "present", else: "absent"

    "snippy: group #{g.prefix}/#{g.key}" <>
      " hosts=[#{hosts}]" <>
      " key_type=#{g.key_type}" <>
      " not_before=#{g.not_before}" <>
      " not_after=#{g.not_after}" <>
      " spki=#{spki}" <>
      " ca_chain=#{ca}" <>
      " password=#{pwd}" <>
      " chain=#{g.chain_validation}" <>
      " cert_source=#{g.cert_source}" <>
      " key_source=#{g.key_source}"
  end

  @doc """
  Compute a stable fingerprint over a list of groups for change detection.
  """
  def fingerprint(groups) do
    groups
    |> Enum.map(fn g ->
      {g.prefix, g.key, g.spki_fingerprint, g.key_fingerprint, Enum.sort(g.hostnames || []),
       g.not_before, g.not_after, g.has_ca_chain?, g.has_password?, g.chain_validation}
    end)
    |> Enum.sort()
    |> :erlang.phash2()
  end
end
