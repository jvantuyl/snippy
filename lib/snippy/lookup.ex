defmodule Snippy.Lookup do
  @moduledoc false

  require Logger

  alias Snippy.Discovery.Group
  alias Snippy.Wildcard

  # All public entry points work over a list of fully-materialized %Group{}s
  # (which carry the private :__ssl_payload__ map). This list comes from
  # either:
  #   * `Snippy.Store.lookup_groups/2` (the live shared scan), or
  #   * the user-supplied `:discovered_certs` (a %Discovery{} from
  #     `Snippy.discover_certificates/1`), in which case the caller must
  #     hydrate the payloads from the Store before calling us — see
  #     `hydrate_groups/1`.

  # ---------------------------------------------------- Hydration helpers ---

  @doc """
  Given a list of Groups from a `%Discovery{}`, return them with their
  `ssl_payload` populated.

  If a group already has a non-nil `ssl_payload` (i.e. it came from an
  isolated discovery), it's returned as-is. If the payload is nil
  (stripped before being placed on a public handle from a shared
  discovery), look the full version up in the Store's ETS by
  `(prefix, key)`. Groups without a materialized entry are dropped silently.
  """
  def hydrate_groups(groups) do
    Enum.flat_map(groups, fn
      %Group{ssl_payload: payload} = g when not is_nil(payload) ->
        [g]

      %Group{prefix: pfx, key: key} ->
        case Snippy.Store.materialized_group(pfx, key) do
          nil -> []
          %Group{} = g -> [g]
        end
    end)
  end

  # ---------------------------------------------------------------- API ---

  @doc """
  Build the SNI fun for a list of materialized groups.

  Returns a closure suitable for the `:sni_fun` :ssl option.
  """
  def sni_fun(groups, opts) do
    scope = build_scope(groups, opts)
    fallback = fallback_entries(groups, scope)
    scoped_groups = scoped(groups, scope)

    fn host ->
      host_norm = normalize(host)
      matches = entries_for_host(scoped_groups, host_norm)

      cond do
        matches != [] -> [certs_keys: ssl_payloads(matches)]
        fallback != [] -> [certs_keys: ssl_payloads(fallback)]
        true -> []
      end
    end
  end

  @doc """
  Build keyword opts for `:ssl.listen/2` (and equivalents).
  """
  def ssl_opts(groups, opts) do
    scope = build_scope(groups, opts)
    fallback = fallback_entries(groups, scope)
    fun = sni_fun(groups, opts)

    [
      sni_fun: fun,
      certs_keys: ssl_payloads(fallback)
    ]
  end

  # ----------------------------------------------------------------- Scope

  defp build_scope(groups, opts) do
    %{
      only: Keyword.get(opts, :only, nil),
      keys: opts |> Keyword.get(:keys, nil) |> normalize_keys(),
      default_hostname: Keyword.get(opts, :default_hostname, nil),
      groups: groups
    }
  end

  defp normalize_keys(nil), do: nil

  defp normalize_keys(list) when is_list(list) do
    Enum.map(list, fn
      a when is_atom(a) -> a |> Atom.to_string() |> String.upcase()
      s when is_binary(s) -> String.upcase(s)
    end)
  end

  defp scoped(groups, %{only: nil, keys: nil}), do: groups

  defp scoped(groups, scope) do
    Enum.filter(groups, fn g -> in_scope?(g, scope) end)
  end

  defp in_scope?(%Group{} = group, scope) do
    key_match?(group.key, scope.keys) or host_match?(group, scope.only)
  end

  defp key_match?(_group_key, nil), do: false
  defp key_match?(group_key, keys), do: group_key in keys

  defp host_match?(_group, nil), do: false

  defp host_match?(%Group{} = group, only_patterns) do
    Enum.any?(only_patterns, fn pattern ->
      Enum.any?(group.hostnames, fn ghost ->
        Wildcard.match?(pattern, ghost) or Wildcard.match?(ghost, pattern) or
          Wildcard.normalize(pattern) == Wildcard.normalize(ghost)
      end)
    end)
  end

  # ------------------------------------------------------- Host resolution

  defp entries_for_host(groups, host_norm) do
    exact =
      Enum.filter(groups, fn g ->
        Enum.any?(g.hostnames, fn pat ->
          case Wildcard.parse(pat) do
            {:exact, labels} -> Enum.join(labels, ".") == host_norm
            _ -> false
          end
        end)
      end)

    if exact != [] do
      exact
    else
      host_labels = String.split(host_norm, ".")
      tail = tl(host_labels || [])

      Enum.filter(groups, fn g ->
        Enum.any?(g.hostnames, fn pat ->
          case Wildcard.parse(pat) do
            {:wild, labels} -> labels == tail
            _ -> false
          end
        end)
      end)
    end
  end

  # ---------------------------------------------------- Fallback entries

  defp fallback_entries([], _scope), do: []

  defp fallback_entries(groups, %{default_hostname: nil} = scope) do
    case scoped(groups, scope) do
      [] -> [hd(groups)]
      [first | _] = scoped_groups -> [first | List.delete(scoped_groups, first)] |> Enum.take(1)
    end
  end

  defp fallback_entries(groups, %{default_hostname: host} = scope) do
    host_norm = normalize(host)
    scoped_groups = scoped(groups, scope)
    matches = entries_for_host(scoped_groups, host_norm)

    cond do
      matches != [] ->
        matches

      scope.only != nil ->
        Logger.warning(
          "snippy: default_hostname #{inspect(host)} excluded by scope; non-SNI fallback empty"
        )

        []

      true ->
        []
    end
  end

  # ---------------------------------------------------- Payload extraction

  defp ssl_payloads(groups) do
    Enum.map(groups, fn %Group{ssl_payload: payload} -> payload end)
  end

  defp normalize(host) when is_binary(host), do: Wildcard.normalize(host)
  defp normalize(host) when is_list(host), do: host |> List.to_string() |> Wildcard.normalize()
end
