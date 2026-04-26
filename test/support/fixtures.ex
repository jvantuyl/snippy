defmodule Snippy.TestFixtures do
  @moduledoc false

  # Drives test/support/gen_fixtures.sh to populate a temp directory with all
  # the certs and keys we need. The script is the source of truth and is
  # documented in its own header. Each call to `setup/0` runs the script in a
  # fresh tempdir so date-relative fixtures (expired/future) are correct.

  @script Path.expand("gen_fixtures.sh", __DIR__)

  def setup do
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

  def cleanup(%{dir: dir}) do
    File.rm_rf!(dir)
  end
end
