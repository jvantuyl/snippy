defmodule Snippy.Wildcard do
  @moduledoc false

  # Hostname normalization and wildcard matching.
  #
  # We use :domainname to parse "real" domain names (which it lowercases and
  # validates). For patterns with a leading "*" label, we strip the "*" and
  # parse the rest, since :domainname rejects "*" as a label character.
  #
  # :domainname does not (yet) handle IDN; for inputs containing non-ASCII
  # bytes we fall back to a simple lowercase + dot-split.

  @doc """
  Parses a host or pattern into a normalized list of labels.

  Returns either:
    - `{:exact, [label, ...]}` for a non-wildcard pattern/host
    - `{:wild, [label, ...]}` for a pattern with a leading `*` label
       (the `*` is stripped from the returned labels list)
  """
  def parse(input) when is_binary(input) do
    trimmed = String.trim_trailing(input, ".")

    case trimmed do
      "*." <> rest ->
        {:wild, labels(rest)}

      "*" ->
        {:wild, []}

      _ ->
        {:exact, labels(trimmed)}
    end
  end

  def parse(input) when is_list(input) do
    input |> List.to_string() |> parse()
  end

  defp labels(""), do: []

  defp labels(name) do
    case DomainName.new(name) do
      {:ok, d} -> DomainName.labels(d)
      {:error, _} -> name |> String.downcase() |> String.split(".")
    end
  end

  @doc """
  Returns the canonical lowercase, dot-trimmed string form of a host.
  """
  def normalize(input) do
    case parse(input) do
      {:exact, ls} -> Enum.join(ls, ".")
      {:wild, ls} -> Enum.join(["*" | ls], ".")
    end
  end

  @doc """
  Returns true if `pattern` matches `host`.

  Pattern may include a single leading `*` label which matches exactly one
  label in the host. No mid-label or multi-label wildcards.
  """
  def match?(pattern, host) do
    case parse(host) do
      # Wildcards on the client/host side don't really make sense; treat
      # as no match.
      {:wild, _} -> false
      {:exact, host_labels} -> match_pattern?(parse(pattern), host_labels)
    end
  end

  defp match_pattern?({:exact, pat_labels}, host_labels), do: pat_labels == host_labels
  defp match_pattern?({:wild, _pat_labels}, []), do: false
  defp match_pattern?({:wild, pat_labels}, [_first | rest]), do: rest == pat_labels

  @doc """
  Returns true if `pattern` is a wildcard pattern.
  """
  def wildcard?(pattern) do
    case parse(pattern) do
      {:wild, _} -> true
      _ -> false
    end
  end

  @doc """
  Returns the number of labels in a host (or pattern, including the wildcard).
  """
  def label_count(input) do
    case parse(input) do
      {:exact, ls} -> length(ls)
      {:wild, ls} -> length(ls) + 1
    end
  end

  @doc """
  Returns the labels-only representation, including the leading `*` for wild.
  """
  def labels_with_wild(input) do
    case parse(input) do
      {:exact, ls} -> ls
      {:wild, ls} -> ["*" | ls]
    end
  end
end
