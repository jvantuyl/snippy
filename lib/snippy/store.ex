defmodule Snippy.Store do
  @moduledoc false

  # Snippy.Store owns a single, shared, broad scan of the env (no prefix
  # filtering). Helpers reach in through API functions; the API functions
  # check ETS atomically first, falling back to a synchronous GenServer.call
  # only on miss. Both successful materializations *and* errors are cached
  # in ETS to avoid recomputation; the API functions unwrap errors back into
  # error returns at the boundary.

  use GenServer
  require Logger

  alias Snippy.Discovery
  alias Snippy.Discovery.Group

  @table Snippy.TableOwner.table_name()

  # ETS row keys:
  #   {:scan_meta}                        -> %{seq, scanned_at, scan_opts}
  #   {:scan, seq, n}                     -> %{var, suffix, slot, kind, val}
  #   {:materialized, prefix_up, key_up}  -> {:ok, %Group{}} | {:error, reason}
  #   {:exact, prefix_up, key_up, host}   -> :present
  #   {:wild,  prefix_up, key_up, labels} -> :present

  @scan_timeout_ms 5_000

  defmodule ScanError do
    defexception [:message, :reason]

    @impl true
    def exception(opts) do
      %__MODULE__{
        reason: opts[:reason],
        message: "snippy: scan failed: #{inspect(opts[:reason])}"
      }
    end
  end

  # ----------------------------------------------------------------- API ---

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Make sure a recent scan exists. Idempotent.

  Calling-process fast path: if the ETS `:scan_meta` row exists and the
  scan is still fresh (or there's no reload interval), return `:ok`
  without calling the GenServer.
  """
  def ensure_scanned(opts \\ []) do
    case current_scan() do
      {:ok, _meta} ->
        :ok

      :missing ->
        synchronous_scan(opts)
    end
  end

  defp synchronous_scan(opts) do
    case GenServer.call(__MODULE__, {:scan, opts}, scan_call_timeout()) do
      :ok -> :ok
      {:error, reason} -> raise ScanError, reason: reason
    end
  end

  defp scan_call_timeout do
    Application.get_env(:snippy, :scan_timeout_ms, @scan_timeout_ms) + 5_000
  end

  defp current_scan do
    case :ets.lookup(@table, :scan_meta) do
      [{:scan_meta, meta}] -> {:ok, meta}
      [] -> :missing
    end
  end

  @doc """
  Look up materialized groups for the given normalized prefixes.

  Errors are silently dropped (they were logged at materialization time).
  """
  def lookup_groups(prefixes, opts \\ []) when is_list(prefixes) do
    :ok = ensure_scanned(opts)

    case_sensitive = Keyword.get(opts, :case_sensitive, true)

    raw_groups = collect_raw_groups(prefixes, case_sensitive)

    Enum.flat_map(raw_groups, fn raw ->
      case fetch_or_materialize(raw, opts) do
        {:ok, group} -> [group]
        {:error, _reason} -> []
      end
    end)
  end

  defp collect_raw_groups(prefixes, case_sensitive) do
    entries = scan_rows()

    entries
    |> Discovery.filter_by_prefixes(prefixes, case_sensitive)
    |> Discovery.group_entries()
  end

  defp scan_rows do
    :ets.tab2list(@table)
    |> Enum.flat_map(fn
      {{:scan, _seq, _n}, payload} -> [payload]
      _ -> []
    end)
  end

  @doc """
  Re-scan and clear all materialized + index rows.
  """
  def reload(opts \\ []) do
    GenServer.call(__MODULE__, {:reload, opts}, scan_call_timeout())
  end

  @doc """
  Test-only: clear all ETS state (scan, materialized, host index, meta)
  and reset the GenServer's seq + reload timer. Used by the test suite to
  isolate cases that exercise the shared Store path. Safe to call in
  production but generally not useful there.
  """
  def __test_reset__ do
    GenServer.call(__MODULE__, :__test_reset__)
  end

  @doc """
  Eager diagnostic discovery: scan + materialize everything matching
  `:prefix`.

  When `:env` is provided in `opts`, runs an **isolated** discovery that
  does *not* touch the shared Store: a one-shot scan + materialize against
  the supplied env, returning a `%Discovery{}` whose groups carry their
  own `ssl_payload` (no Store lookup needed). Suitable for tests and for
  callers who want full control over when materialization happens.

  Without `:env`, runs against the shared Store like normal helpers do.
  """
  def discover(opts) do
    Snippy.OTPCheck.check!()
    prefixes = Discovery.normalize_prefixes!(opts[:prefix])

    if Keyword.has_key?(opts, :env) do
      isolated_discover(prefixes, opts)
    else
      shared_discover(prefixes, opts)
    end
  end

  defp shared_discover(prefixes, opts) do
    :ok = ensure_scanned(opts)

    case_sensitive = Keyword.get(opts, :case_sensitive, true)
    raw_groups = collect_raw_groups(prefixes, case_sensitive)

    {groups, errors} =
      Enum.reduce(raw_groups, {[], []}, fn raw, {gs, es} ->
        case fetch_or_materialize(raw, opts) do
          {:ok, group} -> {[group | gs], es}
          {:error, reason} -> {gs, [{raw.prefix, raw.key, reason} | es]}
        end
      end)

    disc = %Discovery{
      id: make_ref(),
      table: @table,
      default_hostname: opts[:default_hostname],
      reload_interval_ms: opts[:reload_interval_ms],
      groups: Enum.reverse(groups) |> Enum.map(&strip_payload/1),
      errors: Enum.reverse(errors)
    }

    if disc.reload_interval_ms do
      GenServer.cast(__MODULE__, {:set_reload_interval, disc.reload_interval_ms})
    end

    {:ok, disc}
  end

  defp isolated_discover(prefixes, opts) do
    case_sensitive = Keyword.get(opts, :case_sensitive, true)
    entries = Discovery.scan_all(opts)

    raw_groups =
      entries
      |> Discovery.filter_by_prefixes(prefixes, case_sensitive)
      |> Discovery.group_entries()

    {groups, errors} =
      Enum.reduce(raw_groups, {[], []}, fn raw, {gs, es} ->
        case Discovery.materialize_group(raw, opts) do
          {:ok, group} ->
            {[group | gs], es}

          {:error, reason} ->
            require Logger

            Logger.error(
              "snippy: #{inspect(raw.prefix)}/#{raw.key}: #{Discovery.format_error(reason)}; dropping"
            )

            {gs, [{raw.prefix, raw.key, reason} | es]}
        end
      end)

    disc = %Discovery{
      id: make_ref(),
      table: @table,
      default_hostname: opts[:default_hostname],
      reload_interval_ms: opts[:reload_interval_ms],
      groups: Enum.reverse(groups),
      errors: Enum.reverse(errors)
    }

    {:ok, disc}
  end

  defp strip_payload(%Group{} = g), do: %{g | ssl_payload: nil}

  # Used by Snippy.Lookup to retrieve the full group (including __ssl_payload__)
  # given a (prefix, key). Returns nil if not materialized successfully.
  def materialized_group(prefix_up, key_up) do
    case :ets.lookup(@table, {:materialized, prefix_up, key_up}) do
      [{_, {:ok, %Group{} = g}}] -> g
      _ -> nil
    end
  end

  # ------------------------------------------------- Materialization fast path

  defp fetch_or_materialize(raw, opts) do
    key = {:materialized, raw.prefix, raw.key}

    case :ets.lookup(@table, key) do
      [{_, cached}] ->
        cached

      [] ->
        GenServer.call(
          __MODULE__,
          {:materialize, raw, opts},
          materialize_call_timeout()
        )

        case :ets.lookup(@table, key) do
          [{_, cached}] -> cached
          [] -> {:error, :materialize_missing}
        end
    end
  end

  defp materialize_call_timeout do
    Application.get_env(:snippy, :materialize_timeout_ms, 30_000)
  end

  # ---------------------------------------------------------- GenServer ---

  @impl true
  def init([]) do
    {:ok,
     %{
       seq: 0,
       reload_interval_ms: nil,
       reload_timer: nil
     }}
  end

  @impl true
  def handle_call({:scan, opts}, _from, state) do
    case current_scan() do
      {:ok, _meta} ->
        # Someone already scanned while we waited for our turn.
        {:reply, :ok, state}

      :missing ->
        case do_scan(opts) do
          {:ok, new_seq} ->
            state = %{state | seq: new_seq}
            state = maybe_record_reload_interval(state, opts)
            {:reply, :ok, schedule_reload_if_needed(state)}

          {:error, _reason} = err ->
            {:reply, err, state}
        end
    end
  end

  @impl true
  def handle_call({:reload, opts}, _from, state) do
    case do_scan(opts) do
      {:ok, new_seq} ->
        state = %{state | seq: new_seq}
        state = maybe_record_reload_interval(state, opts)
        {:reply, :ok, schedule_reload_if_needed(state)}

      {:error, reason} ->
        Logger.error("snippy: reload scan failed: #{inspect(reason)}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:__test_reset__, _from, state) do
    if state.reload_timer, do: Process.cancel_timer(state.reload_timer)
    :ets.match_delete(@table, {{:scan, :_, :_}, :_})
    :ets.match_delete(@table, {{:materialized, :_, :_}, :_})
    :ets.match_delete(@table, {{:exact, :_, :_, :_}, :_})
    :ets.match_delete(@table, {{:wild, :_, :_, :_}, :_})
    :ets.delete(@table, :scan_meta)
    {:reply, :ok, %{state | seq: 0, reload_interval_ms: nil, reload_timer: nil}}
  end

  @impl true
  def handle_call({:materialize, raw, opts}, _from, state) do
    key = {:materialized, raw.prefix, raw.key}

    case :ets.lookup(@table, key) do
      [_] ->
        {:reply, :ok, state}

      [] ->
        result = run_materialize(raw, opts)
        :ets.insert(@table, {key, result})

        case result do
          {:ok, %Group{} = g} -> populate_host_index(g)
          {:error, reason} -> log_materialization_error(raw, reason)
        end

        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_cast({:set_reload_interval, ms}, state) do
    state = %{state | reload_interval_ms: ms}
    {:noreply, schedule_reload_if_needed(state)}
  end

  @impl true
  def handle_info({:scheduled_reload, seq}, state) do
    if seq == state.seq do
      case do_scan(scan_opts_from_state(state)) do
        {:ok, new_seq} ->
          {:noreply, schedule_reload_if_needed(%{state | seq: new_seq})}

        {:error, reason} ->
          Logger.error("snippy: scheduled reload failed: #{inspect(reason)}")
          {:noreply, schedule_reload_if_needed(state)}
      end
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info({ref, _result}, state) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, state) do
    {:noreply, state}
  end

  # --------------------------------------------------------- internals ---

  defp do_scan(opts) do
    timeout = Application.get_env(:snippy, :scan_timeout_ms, @scan_timeout_ms)
    scan_fn = Application.get_env(:snippy, :scan_fn, &Discovery.scan_all/1)

    task =
      Task.Supervisor.async_nolink(Snippy.TaskSupervisor, fn ->
        scan_fn.(opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task) do
      {:ok, entries} ->
        seq = System.unique_integer([:positive, :monotonic])
        replace_scan(entries, seq, opts)
        {:ok, seq}

      nil ->
        {:error, :scan_timeout}

      {:exit, reason} ->
        {:error, {:scan_crashed, reason}}
    end
  end

  defp replace_scan(entries, seq, opts) do
    # Drop everything dependent on the old scan.
    :ets.match_delete(@table, {{:scan, :_, :_}, :_})
    :ets.match_delete(@table, {{:materialized, :_, :_}, :_})
    :ets.match_delete(@table, {{:exact, :_, :_, :_}, :_})
    :ets.match_delete(@table, {{:wild, :_, :_, :_}, :_})
    :ets.delete(@table, :scan_meta)

    rows =
      entries
      |> Enum.with_index()
      |> Enum.map(fn {entry, n} -> {{:scan, seq, n}, entry} end)

    if rows != [] do
      :ets.insert(@table, rows)
    end

    meta = %{
      seq: seq,
      scanned_at: System.monotonic_time(:millisecond),
      scan_opts: Keyword.take(opts, [:case_sensitive, :env])
    }

    :ets.insert(@table, {:scan_meta, meta})
    :ok
  end

  defp run_materialize(raw, opts) do
    Discovery.materialize_group(raw, opts)
  rescue
    e ->
      Logger.error("snippy: materialize_group raised: #{Exception.message(e)}")
      {:error, {:materialize_exception, Exception.message(e)}}
  end

  defp populate_host_index(%Group{prefix: pfx, key: key, hostnames: hosts}) do
    rows =
      Enum.map(hosts, fn host ->
        case Snippy.Wildcard.parse(host) do
          {:exact, labels} ->
            {{:exact, pfx, key, Enum.join(labels, ".")}, :present}

          {:wild, labels} ->
            {{:wild, pfx, key, labels}, :present}
        end
      end)

    if rows != [] do
      :ets.insert(@table, rows)
    end

    :ok
  end

  defp log_materialization_error(raw, reason) do
    Logger.error(
      "snippy: #{inspect(raw.prefix)}/#{raw.key}: #{Discovery.format_error(reason)}; dropping"
    )
  end

  defp maybe_record_reload_interval(state, opts) do
    case opts[:reload_interval_ms] do
      ms when is_integer(ms) and ms > 0 -> %{state | reload_interval_ms: ms}
      _ -> state
    end
  end

  defp schedule_reload_if_needed(%{reload_interval_ms: nil} = state), do: state

  defp schedule_reload_if_needed(%{reload_interval_ms: ms, seq: seq} = state)
       when is_integer(ms) and ms > 0 do
    if state.reload_timer, do: Process.cancel_timer(state.reload_timer)
    timer = Process.send_after(self(), {:scheduled_reload, seq}, ms)
    %{state | reload_timer: timer}
  end

  defp scan_opts_from_state(_state) do
    # Scheduled reloads always re-scan from real env (or the last persisted
    # opts in scan_meta).
    case current_scan() do
      {:ok, %{scan_opts: opts}} -> opts
      _ -> []
    end
  end
end
