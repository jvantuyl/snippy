defmodule Snippy.MixProject do
  use Mix.Project

  @version "0.8.2"

  def project do
    [
      app: :snippy,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases(),
      name: "Snippy",
      description:
        "Discovers SSL certificates and keys from environment variables and produces " <>
          "configuration for :ssl, Cowboy, Ranch, Bandit, or Thousand Island.",
      source_url: "https://github.com/jvantuyl/snippy",
      package: package(),
      docs: docs(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  def application do
    [
      mod: {Snippy.Application, []},
      extra_applications: [:logger, :ssl, :public_key, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:domainname, "~> 0.1.5"},
      {:castore, "~> 1.0", optional: true},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:rewire, "~> 0.10", only: :test},
      {:stream_data, "~> 1.1", only: :test},
      # test-only server adapters
      {:plug_cowboy, "~> 2.8", only: :test},
      {:ranch, "~> 2.2", only: :test},
      {:bandit, "~> 1.10", only: :test},
      {:thousand_island, "~> 1.4", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/jvantuyl/snippy"},
      files: ~w(lib mix.exs README.md LICENSE.md CHANGELOG.md .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      api_reference: false,
      extras: [
        "README.md": [title: "Overview"],
        "CHANGELOG.md": [title: "Changelog"],
        "LICENSE.md": [title: "License"]
      ],
      authors: ["Jayson Vantuyl"],
      source_ref: "v#{@version}"
    ]
  end

  defp aliases do
    [
      lint: ["format --check-formatted", "compile --warnings-as-errors", "credo --strict"],
      ci: ["lint", "coveralls"]
    ]
  end

  def cli do
    [
      preferred_envs: [
        ci: :test,
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        "coveralls.json": :test,
        "coveralls.post": :test
      ]
    ]
  end
end
