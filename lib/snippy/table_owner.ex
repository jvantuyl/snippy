defmodule Snippy.TableOwner do
  @moduledoc false
  # GenServer whose only job is to own the named ETS table backing all
  # discovered certificate state. By making it a separate process under
  # `:one_for_all` supervision, if this process dies the whole tree restarts
  # (we'll just reload from env).

  use GenServer
  require Logger

  @table :snippy_certs

  def table_name, do: @table

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init([]) do
    _ =
      :ets.new(@table, [
        :named_table,
        :public,
        :bag,
        read_concurrency: true
      ])

    Logger.debug("snippy: created ETS table #{inspect(@table)}")
    {:ok, %{table: @table}}
  end
end
