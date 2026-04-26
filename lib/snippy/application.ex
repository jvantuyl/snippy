defmodule Snippy.Application do
  @moduledoc """
  OTP application callback for Snippy.

  Starts a `:one_for_all` supervisor with the ETS table owner and the
  discovery store as siblings.

  ## Restart intensity

  Web servers often run hot enough that a brief burst of transient errors
  (a flaky NFS mount, a momentary DNS hiccup during a reload, ...) can
  crash the store several times in quick succession. With OTP's stock
  supervisor budget that's enough to take Snippy down entirely.

  The default budget here is forgiving: it tolerates roughly a 20% failure
  rate on a server handling 50 requests per second over a 15-second
  window (about 150 failures). Tune via application config if you want
  tighter or looser bounds:

      # config/runtime.exs
      config :snippy,
        max_restarts: 150,
        max_seconds: 15
  """
  use Application

  @default_max_restarts 150
  @default_max_seconds 15

  @impl true
  def start(_type, _args) do
    Snippy.OTPCheck.check!()

    children = [
      {Task.Supervisor, name: Snippy.TaskSupervisor},
      Snippy.TableOwner,
      Snippy.Store
    ]

    opts = [
      strategy: :one_for_all,
      name: Snippy.Supervisor,
      max_restarts: Application.get_env(:snippy, :max_restarts, @default_max_restarts),
      max_seconds: Application.get_env(:snippy, :max_seconds, @default_max_seconds)
    ]

    Supervisor.start_link(children, opts)
  end
end
