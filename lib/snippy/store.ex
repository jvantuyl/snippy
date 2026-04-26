defmodule Snippy.Store do
  @moduledoc false

  use GenServer
  require Logger

  alias Snippy.Discovery
  alias Snippy.Wildcard

  @table Snippy.TableOwner.table_name()

  # Public API ---------------------------------------------------------------

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Run a one-shot discovery; populate ETS with the resulting groups; return
  a Discovery handle. Each call gets a fresh `:id` and its own rows.
  """
  def discover(opts) do
    case GenServer.call(__MODULE__, {:discover, opts}, 30_000) do
      {:ok, _disc} = ok -> ok
      {:raise, e, stack} -> reraise(e, stack)
    end
  end

  @doc """
  Re-scan the env (and re-read all `_FILE` sources) for an existing handle.
  """
  def reload(%Discovery{} = disc) do
    case GenServer.call(__MODULE__, {:reload, disc}, 30_000) do
      {:ok, _disc} = ok -> ok
      {:error, _} = err -> err
      {:raise, e, stack} -> reraise(e, stack)
    end
  end

  # Server -------------------------------------------------------------------

  @impl true
  def init([]) do
    {:ok, %{handles: %{}}}
  end

  @impl true
  def handle_call({:discover, opts}, _from, state) do
    try do
      id = make_ref()
      groups = Discovery.discover(opts)
      disc = build_handle(id, opts, groups)
      populate_ets(disc, groups)
      schedule_reload(disc)
      state = put_in(state, [:handles, id], {disc, opts})
      invalidate_memo()
      {:reply, {:ok, public_handle(disc)}, state}
    rescue
      e -> {:reply, {:raise, e, __STACKTRACE__}, state}
    end
  end

  @impl true
  def handle_call({:reload, %Discovery{id: id}}, _from, state) do
    case state.handles[id] do
      nil ->
        {:reply, {:error, :unknown_handle}, state}

      {disc, opts} ->
        try do
          groups = Discovery.discover(opts)
          warn_if_no_files(groups)
          delete_ets_rows(disc)
          new_disc = %{disc | groups: strip_payloads(groups)}
          populate_ets(new_disc, groups)
          invalidate_memo()
          state = put_in(state, [:handles, id], {new_disc, opts})
          {:reply, {:ok, public_handle(new_disc)}, state}
        rescue
          e -> {:reply, {:raise, e, __STACKTRACE__}, state}
        end
    end
  end

  @impl true
  def handle_info({:scheduled_reload, id}, state) do
    case state.handles[id] do
      nil ->
        {:noreply, state}

      {disc, opts} ->
        try do
          groups = Discovery.discover(opts)
          delete_ets_rows(disc)
          new_disc = %{disc | groups: strip_payloads(groups)}
          populate_ets(new_disc, groups)
          invalidate_memo()
          state = put_in(state, [:handles, id], {new_disc, opts})
          schedule_reload(new_disc)
          {:noreply, state}
        rescue
          e ->
            Logger.error("snippy: scheduled reload failed: #{Exception.message(e)}")
            schedule_reload(disc)
            {:noreply, state}
        end
    end
  end

  # Internals ----------------------------------------------------------------

  defp build_handle(id, opts, groups) do
    %Discovery{
      id: id,
      table: @table,
      default_hostname: opts[:default_hostname],
      reload_interval_ms: opts[:reload_interval_ms],
      groups: strip_payloads(groups)
    }
  end

  # Strip the internal __ssl_payload__ from each group for the public handle.
  defp strip_payloads(groups) do
    Enum.map(groups, &Map.delete(&1, :__ssl_payload__))
  end

  # Public handle: hide internal id from typespec but keep it for reload calls.
  defp public_handle(%Discovery{} = disc), do: disc

  defp populate_ets(%Discovery{id: id}, groups) do
    rows =
      Enum.flat_map(groups, fn group ->
        ssl_map = group.__ssl_payload__
        group_key = {group.prefix, group.key}

        host_rows =
          Enum.map(group.hostnames, fn host ->
            case Wildcard.parse(host) do
              {:exact, labels} ->
                {{:exact, id, Enum.join(labels, ".")}, group_key, ssl_map, group}

              {:wild, labels} ->
                {{:wild, id, labels}, group_key, ssl_map, group}
            end
          end)

        # A "group" row that lets us iterate by group key for `:keys` filtering.
        group_row = {{:group, id, group_key}, ssl_map, group}

        [group_row | host_rows]
      end)

    if rows != [] do
      true = :ets.insert(@table, rows)
    end

    # Default-hostname ssl_map (precomputed once, used for non-SNI fallback).
    case default_group(groups, %Discovery{id: id, default_hostname: nil}) do
      nil -> :ok
      _g -> :ok
    end

    :ok
  end

  defp delete_ets_rows(%Discovery{id: id}) do
    :ets.match_delete(@table, {{:exact, id, :_}, :_, :_, :_})
    :ets.match_delete(@table, {{:wild, id, :_}, :_, :_, :_})
    :ets.match_delete(@table, {{:group, id, :_}, :_, :_})
    :ok
  end

  defp default_group([], _disc), do: nil

  defp default_group(groups, %Discovery{default_hostname: nil}), do: hd(groups)

  defp default_group(groups, %Discovery{default_hostname: host}) do
    target = Wildcard.normalize(host)

    Enum.find(groups, fn g ->
      Enum.any?(g.hostnames, fn pattern ->
        Wildcard.match?(pattern, target)
      end)
    end) || hd(groups)
  end

  defp schedule_reload(%Discovery{reload_interval_ms: nil}), do: :ok

  defp schedule_reload(%Discovery{reload_interval_ms: ms, id: id})
       when is_integer(ms) and ms > 0 do
    Process.send_after(self(), {:scheduled_reload, id}, ms)
    :ok
  end

  defp warn_if_no_files(groups) do
    has_files? =
      Enum.any?(groups, fn g ->
        g.cert_source == :file or g.key_source == :file
      end)

    unless has_files? do
      Logger.warning(
        "snippy: reload requested but no _FILE sources are configured; result will be unchanged"
      )
    end
  end

  defp invalidate_memo do
    if Code.ensure_loaded?(Snippy.Lookup) and function_exported?(Memoize, :invalidate, 1) do
      try do
        Memoize.invalidate(Snippy.Lookup)
      rescue
        _ -> :ok
      end
    end

    :ok
  end
end
