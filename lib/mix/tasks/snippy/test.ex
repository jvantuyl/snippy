defmodule Mix.Tasks.Snippy.Test do
  @moduledoc """
  Runs Snippy discovery against the current environment and prints a summary
  of every discovered certificate group, eliding any password material.

      mix snippy.test PREFIX [PREFIX ...]
      mix snippy.test --prefix PREFIX [--prefix PREFIX ...]

  Options:
    --prefix PREFIX            (repeatable) one or more prefixes
    --case-insensitive         disable case-sensitive matching
    --default-hostname HOST    pin the SNI fallback host
    --reload N                 reload interval in ms (no-op for one-shot)
    --public-ca MODE           auto | always | never
    --only PATTERN             (repeatable) scope SNI/opts to a host pattern
    --key NAME                 (repeatable) scope SNI/opts to a group key
    --quiet                    suppress per-group detail; just print counts
  """

  @shortdoc "test snippy discovery"

  use Mix.Task
  alias Snippy.Decoder
  alias Snippy.Discovery

  @switches [
    prefix: :keep,
    case_insensitive: :boolean,
    default_hostname: :string,
    reload: :integer,
    public_ca: :string,
    only: :keep,
    key: :keep,
    quiet: :boolean
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, positional, _} = OptionParser.parse(args, strict: @switches)

    prefixes = Keyword.get_values(opts, :prefix) ++ positional

    if prefixes == [] do
      Mix.shell().error("snippy.test: no prefixes provided")
      exit({:shutdown, 1})
    end

    discover_opts = [
      prefix: prefixes,
      case_sensitive: not Keyword.get(opts, :case_insensitive, false),
      default_hostname: Keyword.get(opts, :default_hostname),
      reload_interval_ms: Keyword.get(opts, :reload),
      public_ca_validation: parse_public_ca(Keyword.get(opts, :public_ca, "auto"))
    ]

    only = Keyword.get_values(opts, :only)
    keys = Keyword.get_values(opts, :key)
    quiet? = Keyword.get(opts, :quiet, false)

    {:ok, disc} = Snippy.discover_certificates(discover_opts)

    print_groups(disc.groups, quiet?)
    print_errors(disc.errors)

    scope_opts = [only: only, keys: keys] |> Enum.reject(fn {_, v} -> v == [] end)

    if scope_opts != [] do
      print_scope_summary(disc, scope_opts)
    end

    :ok
  end

  defp parse_public_ca("auto"), do: :auto
  defp parse_public_ca("always"), do: :always
  defp parse_public_ca("never"), do: :never
  defp parse_public_ca(other), do: raise(ArgumentError, "invalid --public-ca: #{other}")

  defp print_groups([], _quiet?) do
    Mix.shell().info("no certificate groups discovered")
  end

  defp print_groups(groups, true) do
    Mix.shell().info("Discovered #{length(groups)} group(s).")
  end

  defp print_groups(groups, false) do
    Mix.shell().info("Discovered #{length(groups)} group(s):\n")
    Enum.each(groups, &print_group/1)
  end

  defp print_group(g) do
    out = IO.ANSI.bright()
    reset = IO.ANSI.reset()

    Mix.shell().info("#{out}#{g.prefix}/#{g.key}#{reset}")
    Mix.shell().info("  cert source       : #{g.cert_source}")
    Mix.shell().info("  key source        : #{g.key_source}")
    Mix.shell().info("  key type          : #{g.key_type}")
    Mix.shell().info("  hostnames         : #{Enum.join(g.hostnames, ", ")}")
    Mix.shell().info("  not_before        : #{g.not_before}")
    Mix.shell().info("  not_after         : #{g.not_after}")
    Mix.shell().info("  spki fingerprint  : #{Decoder.fingerprint_hex(g.spki_fingerprint)}")
    Mix.shell().info("  key fingerprint   : #{Decoder.fingerprint_hex(g.key_fingerprint)}")
    Mix.shell().info("  ca chain          : #{if g.has_ca_chain?, do: "present", else: "absent"}")

    Mix.shell().info(
      "  password          : #{if g.has_password?, do: "present (elided)", else: "absent"}"
    )

    Mix.shell().info("  ocsp stapling     : #{g.ocsp_stapling?}")
    Mix.shell().info("  chain validation  : #{g.chain_validation}")
    Mix.shell().info("")
  end

  defp print_errors([]), do: :ok

  defp print_errors(errors) do
    Mix.shell().info("\n#{IO.ANSI.red()}Materialization errors:#{IO.ANSI.reset()}\n")

    Enum.each(errors, fn {prefix, key, reason} ->
      Mix.shell().info("  #{prefix}/#{key}: #{Discovery.format_error(reason)}")
    end)

    Mix.shell().info("")
  end

  defp print_scope_summary(disc, scope_opts) do
    total = length(disc.groups)

    survivors =
      Snippy.ssl_opts(
        Keyword.merge(scope_opts,
          discovered_certs: disc
        )
      )

    survivor_count = length(Keyword.get(survivors, :certs_keys, []))

    Mix.shell().info(
      "scope filter: #{inspect(scope_opts)} -> #{survivor_count} fallback / #{total} total"
    )
  end
end
