defmodule Snippy.OTPCheck do
  @moduledoc false

  alias Snippy.OtpInfo

  @min_otp 25

  @otp_release OtpInfo.release()

  if @otp_release < @min_otp do
    raise CompileError,
      description: "Snippy requires OTP >= #{@min_otp}, got #{@otp_release}"
  end

  def check! do
    otp = OtpInfo.release()

    if otp < @min_otp do
      raise "Snippy requires OTP >= #{@min_otp}, got #{otp}"
    end

    :ok
  end
end
