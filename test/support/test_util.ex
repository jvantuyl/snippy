defmodule Snippy.TestUtil do
  @moduledoc """
  Test utility helpers shared across `Snippy` test modules.
  """

  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  @doc """
  Suppresses noisy log/IO output emitted while running `body`.

  Use this around test bodies (or sub-blocks) that exercise production
  code paths that legitimately emit logs we don't want spamming the test
  output. Tests that need to *assert* on log content should use
  `ExUnit.CaptureLog.capture_log/1` directly so they receive the
  captured string back.

  Set the `LOUD` env var to disable suppression; useful when debugging
  a test interactively to see what's being logged.

      quiet do
        {:ok, _disc} = Snippy.discover_certificates(prefix: "APP", env: env)
      end
  """
  defmacro quiet(do: body) do
    quote location: :keep do
      if System.get_env("LOUD") do
        unquote(body)
      else
        capture_io(fn -> capture_log(fn -> unquote(body) end) end)
      end
    end
  end
end
