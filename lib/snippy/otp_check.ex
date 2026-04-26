defmodule Snippy.OTPCheck do
  @moduledoc false

  @min_otp 25

  @otp_release :erlang.system_info(:otp_release) |> List.to_integer()

  if @otp_release < @min_otp do
    raise CompileError,
      description: "Snippy requires OTP >= #{@min_otp}, got #{@otp_release}"
  end

  def check! do
    otp = :erlang.system_info(:otp_release) |> List.to_integer()

    if otp < @min_otp do
      raise "Snippy requires OTP >= #{@min_otp}, got #{otp}"
    end

    :ok
  end
end
