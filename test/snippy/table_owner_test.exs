defmodule Snippy.TableOwnerTest do
  use ExUnit.Case, async: true

  test "table_name/0 returns the named ETS table atom" do
    assert Snippy.TableOwner.table_name() == :snippy_certs
  end
end
