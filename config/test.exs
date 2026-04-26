import Config

# Quiet down logging during tests. The TestUtil.quiet/1 macro captures
# anything that does still emit a log message, but we still narrow the
# global level to skip startup chatter from us and our adapter deps that
# fire before any test (and are therefore unreachable from quiet/1).
#
# Set the LOUD env var to undo this (matches TestUtil.quiet/1's opt-out).
if System.get_env("LOUD") in [nil, ""] do
  # Keep the primary level at :debug so ExUnit.CaptureLog still receives
  # everything for tests that opt into capture (TestUtil.quiet/1, with_log,
  # etc.). The default *handler*, on the other hand, only emits :warning
  # and above, so startup chatter that fires before any test is silent.
  config :logger, :default_handler, level: :warning
end
