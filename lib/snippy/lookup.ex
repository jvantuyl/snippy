defmodule Snippy.Lookup do
  @moduledoc false

  use Memoize
  require Logger

  alias Snippy.Discovery
  alias Snippy.Wildcard

  # Public entry points -------------------------------------------------------

  @doc """
  Build the SNI fun for a Discovery.
  """
  def sni_fun(%Discovery{} = disc, opts) do
    scope = build_scope(disc, opts)
    fallback = fallback_entries(disc, scope)

    fn host ->
      entries = entries_for(disc.id, normalize(host), scope)

      cond do
        entries != [] ->
          [certs_keys: Enum.map(entries, fn {_gk, ssl_map, _g} -> ssl_map end)]

        fallback != [] ->
          [certs_keys: Enum.map(fallback, fn {_gk, ssl_map, _g} -> ssl_map end)]

        true ->
          []
      end
    end
  end

  @doc """
  Build keyword opts for `:ssl.listen/2` (and equivalents).

  Always includes `:sni_fun` and a `:certs_keys` snapshot built from the
  default hostname (or the union of scoped groups when no default).
  """
  def ssl_opts(%Discovery{} = disc, opts) do
    scope = build_scope(disc, opts)
    fallback = fallback_entries(disc, scope)
    ssl_fun = sni_fun(disc, opts)

    [
      sni_fun: ssl_fun,
      certs_keys: Enum.map(fallback, fn {_gk, ssl_map, _g} -> ssl_map end)
    ]
  end

  # Memoized lookup -----------------------------------------------------------

  defmemo entries_for(disc_id, host_norm, scope_id), expires_in: :infinity do
    do_lookup(disc_id, host_norm, scope_id)
  end

  defp do_lookup(disc_id, host_norm, scope_id) do
    table = Snippy.TableOwner.table_name()
    {_scope_id_value, scope} = scope_id_extract(scope_id)

    exact = :ets.lookup(table, {:exact, disc_id, host_norm})
    matches = entries_from_rows(exact)

    matches =
      if matches == [] do
        host_labels = host_norm |> String.split(".")
        wild_matches = scan_wildcards(table, disc_id, host_labels)
        wild_matches
      else
        matches
      end

    apply_scope(matches, scope)
  end

  # ETS row scanning ----------------------------------------------------------

  defp entries_from_rows(rows) do
    Enum.map(rows, fn {_key, gk, ssl_map, group} -> {gk, ssl_map, group} end)
  end

  defp scan_wildcards(_table, _disc_id, []), do: []

  defp scan_wildcards(table, disc_id, [_first | rest]) do
    rows = :ets.lookup(table, {:wild, disc_id, rest})
    entries_from_rows(rows)
  end

  # Scope filtering -----------------------------------------------------------

  defp build_scope(disc, opts) do
    only = Keyword.get(opts, :only, nil)
    keys = Keyword.get(opts, :keys, nil) |> normalize_keys()

    %{
      only: only,
      keys: keys,
      default_hostname: disc.default_hostname,
      scope_id: scope_id_for(only, keys)
    }
  end

  defp normalize_keys(nil), do: nil

  defp normalize_keys(list) when is_list(list) do
    Enum.map(list, fn
      a when is_atom(a) -> a |> Atom.to_string() |> String.upcase()
      s when is_binary(s) -> String.upcase(s)
    end)
  end

  defp scope_id_for(only, keys) do
    {only && Enum.sort(only), keys && Enum.sort(keys)}
  end

  defp scope_id_extract({_only, _keys} = id), do: {id, %{only: elem(id, 0), keys: elem(id, 1)}}

  defp apply_scope(entries, %{only: nil, keys: nil}), do: entries

  defp apply_scope(entries, scope) do
    Enum.filter(entries, fn {{_prefix, group_key} = _gk, _ssl_map, group} ->
      key_match?(group_key, scope.keys) or host_match?(group, scope.only)
    end)
  end

  defp key_match?(_group_key, nil), do: false
  defp key_match?(group_key, keys), do: group_key in keys

  defp host_match?(_group, nil), do: false

  defp host_match?(group, only_patterns) do
    Enum.any?(only_patterns, fn pattern ->
      Enum.any?(group.hostnames, fn ghost ->
        # only_patterns are user-supplied filter patterns; they match against
        # the group's advertised hostnames using wildcard semantics.
        Wildcard.match?(pattern, ghost) or Wildcard.match?(ghost, pattern) or
          Wildcard.normalize(pattern) == Wildcard.normalize(ghost)
      end)
    end)
  end

  # Fallback entries (non-SNI clients) ---------------------------------------

  defp fallback_entries(%Discovery{groups: []}, _scope), do: []

  defp fallback_entries(%Discovery{} = disc, scope) do
    table = Snippy.TableOwner.table_name()

    case disc.default_hostname do
      nil ->
        # Use the first group whose key/host passes scope, or the first group.
        scoped_groups =
          disc.groups
          |> Enum.filter(fn g -> in_scope?(g, scope) end)

        chosen = if scoped_groups == [], do: hd(disc.groups), else: hd(scoped_groups)
        gk = {chosen.prefix, chosen.key}
        rows = :ets.lookup(table, {:group, disc.id, gk})
        Enum.map(rows, fn {_key, ssl_map, group} -> {gk, ssl_map, group} end)

      host ->
        host_norm = normalize(host)
        rows = :ets.lookup(table, {:exact, disc.id, host_norm})

        rows =
          if rows == [] do
            host_labels = String.split(host_norm, ".")
            scan_wildcards_raw(table, disc.id, host_labels)
          else
            rows
          end

        scoped =
          rows
          |> Enum.map(fn {_key, gk, ssl_map, group} -> {gk, ssl_map, group} end)
          |> apply_scope(scope)

        if scoped == [] and scope.only != nil do
          Logger.warning(
            "snippy: default_hostname #{inspect(host)} excluded by scope; non-SNI fallback empty"
          )
        end

        scoped
    end
  end

  defp scan_wildcards_raw(_table, _disc_id, []), do: []

  defp scan_wildcards_raw(table, disc_id, [_first | rest]) do
    :ets.lookup(table, {:wild, disc_id, rest})
  end

  defp in_scope?(_group, %{only: nil, keys: nil}), do: true

  defp in_scope?(group, scope) do
    gk = {group.prefix, group.key}
    key_match?(gk, scope.keys) or host_match?(group, scope.only)
  end

  defp normalize(host) when is_binary(host), do: Wildcard.normalize(host)
  defp normalize(host) when is_list(host), do: host |> List.to_string() |> Wildcard.normalize()
end
