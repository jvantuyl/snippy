defmodule Snippy.WildcardTest do
  use ExUnit.Case, async: true

  alias Snippy.Wildcard

  test "exact match" do
    assert Wildcard.match?("api.example.com", "api.example.com")
    refute Wildcard.match?("api.example.com", "other.example.com")
  end

  test "case insensitive" do
    assert Wildcard.match?("API.Example.Com", "api.example.com")
    assert Wildcard.match?("api.example.com", "API.EXAMPLE.COM")
  end

  test "leftmost label wildcard" do
    assert Wildcard.match?("*.example.com", "api.example.com")
    assert Wildcard.match?("*.example.com", "x.example.com")
    refute Wildcard.match?("*.example.com", "api.deep.example.com")
    refute Wildcard.match?("*.example.com", "example.com")
  end

  test "trailing dot is ignored" do
    assert Wildcard.match?("example.com", "example.com.")
    assert Wildcard.match?("example.com.", "example.com")
  end

  test "wildcard? identifies wildcard patterns" do
    assert Wildcard.wildcard?("*.example.com")
    refute Wildcard.wildcard?("api.example.com")
  end

  test "normalize lowercases and trims" do
    assert Wildcard.normalize("API.EXAMPLE.COM.") == "api.example.com"
    assert Wildcard.normalize("*.Example.Com") == "*.example.com"
  end

  test "label_count includes the wildcard label" do
    assert Wildcard.label_count("api.example.com") == 3
    assert Wildcard.label_count("*.example.com") == 3
    assert Wildcard.label_count("*") == 1
    assert Wildcard.label_count("example.com.") == 2
  end

  test "labels_with_wild includes the leading * for wildcard patterns" do
    assert Wildcard.labels_with_wild("api.example.com") == ["api", "example", "com"]
    assert Wildcard.labels_with_wild("*.example.com") == ["*", "example", "com"]
    assert Wildcard.labels_with_wild("*") == ["*"]
  end

  test "match? rejects host-side wildcards" do
    refute Wildcard.match?("api.example.com", "*.example.com")
    refute Wildcard.match?("*.example.com", "*.example.com")
  end

  test "non-ASCII host falls back to lowercase + dot-split" do
    # The :domainname dependency rejects non-ASCII labels; we should get a
    # case-folded, dot-split result anyway.
    result = Wildcard.normalize("München.Example.Com")
    assert result == "münchen.example.com"
  end

  test "parse handles charlists" do
    assert {:exact, ["api", "example", "com"]} == Wildcard.parse(~c"api.example.com")
    assert {:wild, ["example", "com"]} == Wildcard.parse(~c"*.example.com")
  end

  test "match? handles empty wildcard" do
    assert Wildcard.match?("*", "anything")
    refute Wildcard.match?("*", "deep.host.com")
  end

  test "wildcard? identifies bare star" do
    assert Wildcard.wildcard?("*")
  end

  test "wildcard pattern does not match an empty host" do
    # Hits the `[] -> false` branch in match?/2.
    refute Wildcard.match?("*.example.com", "")
  end

  test "parse on empty input returns no labels" do
    assert {:exact, []} = Wildcard.parse("")
  end
end
