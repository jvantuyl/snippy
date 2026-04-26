defmodule Snippy.TestFixtures do
  @moduledoc false

  # Drives test/support/gen_fixtures.sh to populate a temp directory with all
  # the certs and keys we need. The script is the source of truth and is
  # documented in its own header.
  #
  # The fixture set is generated **once per test run** and cached in
  # :persistent_term; every test's `setup do` returns the same shared map.
  # Tests are read-only consumers of the fixture files (they only read
  # paths/PEM strings into env-var values), so a single tempdir is safe
  # across the whole suite. Cleanup is registered as a single
  # System.at_exit/1 hook the first time the fixtures are built.

  @script Path.expand("gen_fixtures.sh", __DIR__)
  @key {__MODULE__, :fixtures}
  @lock {__MODULE__, :lock}

  def setup do
    case :persistent_term.get(@key, :missing) do
      :missing -> build_once()
      fx -> fx
    end
  end

  # cleanup/1 is a no-op: the shared tempdir lives for the whole test run
  # and is removed by the System.at_exit/1 hook registered in build_once/0.
  def cleanup(_fx), do: :ok

  defp build_once do
    # Serialize concurrent first-time callers with a named global lock so
    # we only run gen_fixtures.sh once even under async tests.
    :global.set_lock({@lock, self()})

    try do
      case :persistent_term.get(@key, :missing) do
        :missing ->
          fx = generate()
          :persistent_term.put(@key, fx)
          register_cleanup(fx.dir)
          fx

        fx ->
          fx
      end
    after
      :global.del_lock({@lock, self()})
    end
  end

  defp generate do
    dir = Path.join(System.tmp_dir!(), "snippy_fixtures_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    {output, 0} = System.cmd(@script, [dir], stderr_to_stdout: true)
    _ = output

    paths = %{
      ca_cert: Path.join(dir, "ca.pem"),
      ca_key: Path.join(dir, "ca.key"),
      a_cert: Path.join(dir, "a.pem"),
      a_key: Path.join(dir, "a.key"),
      b_cert: Path.join(dir, "b.pem"),
      b_key: Path.join(dir, "b.key"),
      b_key_enc: Path.join(dir, "b.enc.key"),
      wild_cert: Path.join(dir, "wild.pem"),
      wild_key: Path.join(dir, "wild.key"),
      ec_cert: Path.join(dir, "ec.pem"),
      ec_key: Path.join(dir, "ec.key"),
      ed_cert: Path.join(dir, "ed.pem"),
      ed_key: Path.join(dir, "ed.key"),
      nosan_cert: Path.join(dir, "nosan.pem"),
      nosan_key: Path.join(dir, "nosan.key"),
      b_key_enc_legacy: Path.join(dir, "b.enc.legacy.key"),
      a_key_traditional: Path.join(dir, "a.traditional.key"),
      dsa_key: Path.join(dir, "dsa.key"),
      expired_cert: Path.join(dir, "expired.pem"),
      expired_key: Path.join(dir, "expired.key"),
      future_cert: Path.join(dir, "future.pem"),
      future_key: Path.join(dir, "future.key"),
      pwd_file: Path.join(dir, "pwd.txt"),
      pwd_file_notrim: Path.join(dir, "pwd_notrim.txt")
    }

    pem = Map.new(paths, fn {k, p} -> {k, File.read!(p)} end)
    %{dir: dir, paths: paths, pem: pem}
  end

  defp register_cleanup(dir) do
    System.at_exit(fn _ -> File.rm_rf!(dir) end)
  end
end
