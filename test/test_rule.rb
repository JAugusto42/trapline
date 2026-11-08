# frozen_string_literal: true

require "test_helper"

class TestRule < Minitest::Test
  YAML_SRC = <<~YAML
    rules:
      - id: eval-user-input
        message: Avoid eval with $X
        severity: ERROR
        languages: [ruby]
        custom-key: keep me
        patterns:
          - pattern: eval($X)
          - pattern-not: eval("...")
  YAML

  def test_roundtrip_keeps_unknown_keys_and_order
    rule = Trapline::Rule.parse(YAML_SRC)
    out = rule.to_yaml
    assert_includes out, "custom-key: keep me"
    assert_includes out, "- pattern: eval($X)"
    assert_includes out, "- pattern-not: eval(\"...\")"
    assert_operator out.index("id:"), :<, out.index("message:")
    assert_equal rule.to_h, Trapline::Rule.parse(out).to_h
  end

  def test_multiline_strings_use_literal_blocks
    rule = Trapline::Rule.new("id" => "x", "pattern-inside" => "def $F(...)\n  ...\nend\n")
    assert_includes rule.to_yaml, "pattern-inside: |"
  end

  def test_quotes_only_when_needed
    rule = Trapline::Rule.new("id" => "x", "a" => "$X.to_i", "b" => "{...}", "c" => "yes", "d" => "10.0")
    yaml = rule.to_yaml
    assert_includes yaml, "a: $X.to_i"
    assert_includes yaml, "b: \"{...}\""
    refute_includes yaml, "c: yes"
    assert_equal rule.to_h, Trapline::Rule.parse(yaml).to_h
  end

  def test_merge_fields
    rule = Trapline::Rule.parse(YAML_SRC)
    rule.merge_fields("severity" => "WARNING", "languages" => "ruby, python",
                      "metadata" => { "cwe" => "CWE-95", "references" => "https://a\nhttps://b", "confidence" => "" })
    assert_equal "WARNING", rule.severity
    assert_equal %w[ruby python], rule.languages
    assert_equal ["CWE-95"], rule.metadata["cwe"]
    assert_equal ["https://a", "https://b"], rule.metadata["references"]
    refute rule.metadata.key?("confidence")
  end

  def test_parse_errors_carry_line
    err = assert_raises(Trapline::ParseError) { Trapline::RuleFile.parse("rules:\n  - id: [x\n") }
    assert_match(/line/, err.message)
    assert_raises(Trapline::ParseError) { Trapline::RuleFile.parse("") }
    assert_raises(Trapline::ParseError) { Trapline::RuleFile.parse("foo: bar") }
  end
end
