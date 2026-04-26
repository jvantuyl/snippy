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
  """

  @shortdoc "test snippy discovery"

  use Mix.Task
  alias Snippy.Decoder

  @switches [
    prefix: :keep,
    case_insensitive: :boolean,
    default_hostname: :string,
    reload: :integer,
    public_ca: :string,
    only: :keep,
    key: :keep
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, positional, _} = OptionParser.parse(args, strict: @switches)

    prefixes =
      Keyword.get_values(opts, :prefix) ++ positional

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

    case Snippy.discover_certificates(discover_opts) do
      {:ok, disc} ->
        print_groups(disc.groups)
        scope_opts = [only: only, keys: keys] |> Enum.reject(fn {_, v} -> v == [] end)

        if scope_opts != [] do
          Mix.shell().info("\nscope filter: #{inspect(scope_opts)}")
        end

        :ok
    end
  end

  defp parse_public_ca("auto"), do: :auto
  defp parse_public_ca("always"), do: :always
  defp parse_public_ca("never"), do: :never
  defp parse_public_ca(other), do: raise(ArgumentError, "invalid --public-ca: #{other}")

  defp print_groups([]) do
    Mix.shell().info("no certificate groups discovered")
  end

  defp print_groups(groups) do
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
end
