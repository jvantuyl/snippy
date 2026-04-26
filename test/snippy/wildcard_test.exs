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
end
