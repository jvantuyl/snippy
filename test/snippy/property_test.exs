defmodule Snippy.PropertyTest do
  @moduledoc """
  Property-based tests for the matching primitives that decisions across
  Snippy's hot paths depend on:

    * `Snippy.Wildcard` parse/normalize round-trips and match invariants.
    * `Snippy.Discovery.scan_all/1` + `filter_by_prefixes/3`: every var in
      the scan output is a real env var; every prefix-matched entry's
      derived (prefix, key) is consistent with its var name and suffix.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Snippy.Discovery
  alias Snippy.Wildcard

  # ---- Wildcard ----

  describe "Wildcard parse/normalize" do
    property "normalize/1 is idempotent" do
      check all(host <- ascii_host()) do
        normalized = Wildcard.normalize(host)
        assert Wildcard.normalize(normalized) == normalized
      end
    end

    property "normalize/1 produces lowercase output for ASCII hosts" do
      check all(host <- ascii_host()) do
        normalized = Wildcard.normalize(host)
        # We don't enforce a particular dot pattern, but the output must
        # not contain any ASCII uppercase characters.
        refute String.match?(normalized, ~r/[A-Z]/)
      end
    end

    property "exact patterns match their own normalized form" do
      check all(host <- ascii_host(:exact)) do
        normalized = Wildcard.normalize(host)
        assert Wildcard.match?(host, normalized)
        assert Wildcard.match?(normalized, host)
      end
    end

    property "wildcards never match a host with the wrong number of labels" do
      check all(base <- multi_label_host()) do
        pattern = "*." <> base
        # `*.foo.com` must not match `foo.com` itself.
        refute Wildcard.match?(pattern, base)
        # ...nor `deep.x.foo.com` (two labels above base).
        refute Wildcard.match?(pattern, "deep.x." <> base)
        # ...but does match exactly one label above.
        assert Wildcard.match?(pattern, "child." <> base)
      end
    end

    property "label_count agrees with parse" do
      check all(host <- ascii_host()) do
        case Wildcard.parse(host) do
          {:exact, ls} -> assert Wildcard.label_count(host) == length(ls)
          {:wild, ls} -> assert Wildcard.label_count(host) == length(ls) + 1
        end
      end
    end
  end

  # ---- Discovery scan_all + filter_by_prefixes ----

  describe "Discovery scan_all/1" do
    property "every output entry came from an env var with a known suffix" do
      check all(env <- env_map()) do
        entries = Discovery.scan_all(env: env)
        suffixes = Discovery.suffixes() |> Enum.map(&elem(&1, 0))

        for e <- entries do
          assert e.suffix in suffixes
          assert Map.has_key?(env, e.var)
          assert env[e.var] == e.val
          assert String.ends_with?(e.var, e.suffix)
        end
      end
    end

    property "scan output never contains entries whose var equals the suffix" do
      # i.e. there's always at least one prefix/key character before the suffix.
      check all(env <- env_map()) do
        for e <- Discovery.scan_all(env: env) do
          assert byte_size(e.var) > byte_size(e.suffix)
        end
      end
    end
  end

  describe "Discovery filter_by_prefixes/3" do
    property "every filtered entry's var begins with one of the prefixes" do
      check all(
              env <- env_map(),
              prefix <- alpha_prefix(),
              max_runs: 50
            ) do
        entries = Discovery.scan_all(env: env)
        out = Discovery.filter_by_prefixes(entries, [prefix])

        for e <- out do
          assert String.starts_with?(e.var, prefix <> "_")
          assert String.ends_with?(e.var, e.suffix)
          # Reconstruct: prefix + "_" + key + suffix == var
          assert e.var == prefix <> "_" <> e.key <> e.suffix
          assert e.prefix == prefix
        end
      end
    end

    property "filtering with the empty prefix accepts every scan entry" do
      check all(env <- env_map()) do
        entries = Discovery.scan_all(env: env)
        out = Discovery.filter_by_prefixes(entries, [""])
        assert length(out) == length(entries)
      end
    end
  end

  # ---- generators ----

  defp ascii_host do
    one_of([ascii_host(:exact), ascii_host(:wild)])
  end

  defp ascii_host(:exact) do
    list_of(label(), min_length: 1, max_length: 4)
    |> map(&Enum.join(&1, "."))
  end

  defp ascii_host(:wild) do
    list_of(label(), min_length: 1, max_length: 3)
    |> map(fn ls -> "*." <> Enum.join(ls, ".") end)
  end

  # Hosts with at least two labels (so they always contain a `.`).
  defp multi_label_host do
    list_of(label(), min_length: 2, max_length: 4)
    |> map(&Enum.join(&1, "."))
  end

  defp label do
    string(:alphanumeric, min_length: 1, max_length: 12)
  end

  defp alpha_prefix do
    string(?A..?Z |> Enum.to_list(), min_length: 2, max_length: 6)
  end

  defp env_map do
    map_of(env_var_name(), string(:printable, max_length: 40), max_length: 16)
  end

  # Build env-var names that look plausible: an upper-letter prefix segment
  # plus an optional suffix segment that's sometimes one of ours.
  defp env_var_name do
    bind(
      tuple({alpha_prefix(), string(?A..?Z |> Enum.to_list(), min_length: 1, max_length: 8)}),
      fn {pfx, body} ->
        suffix_pool =
          Discovery.suffixes()
          |> Enum.map(&elem(&1, 0))
          |> Kernel.++(["", "_FOO", "_BAR"])

        bind(member_of(suffix_pool), fn s ->
          constant(pfx <> "_" <> body <> s)
        end)
      end
    )
  end
end
