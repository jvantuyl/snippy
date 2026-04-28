defmodule Snippy.OtpInfo do
  @moduledoc false

  # Tiny indirection over :erlang.system_info(:otp_release) so the OTP
  # version check is unit-testable via `rewire` without touching the
  # Erlang-level :erlang module.

  @spec release() :: integer()
  def release do
    :erlang.system_info(:otp_release) |> List.to_integer()
  end
end
