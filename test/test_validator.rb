# frozen_string_literal: true

require "test_helper"

class TestValidator < Minitest::Test
  def validate(yaml)
    Trapline::Validator.new.validate(yaml)
  end

  def messages(result, level = "error")
    result.issues.select { |i| i.level == level }.map(&:message).join("\n")
  end

  def base(extra)
    "rules:\n  - id: r\n    message: m\n    severity: ERROR\n    languages: [ruby]\n#{extra}"
  end

  def test_valid_rule
    r = validate(base("    pattern: eval($X)\n    metadata:\n      cwe: ['CWE-95: Eval Injection']\n      references: [https://x]\n"))
    assert r.valid?, r.issues.inspect
    assert_empty r.issues.reject { |i| i.level == "info" }
  end

  def test_required_keys
    r = validate("rules:\n  - pattern: x\n")
    msg = messages(r)
    assert_match(/`id` is required/, msg)
    assert_match(/`message` is required/, msg)
    assert_match(/`severity` is required/, msg)
    assert_match(/`languages`/, msg)
  end

  def test_bad_severity_and_multiple_top_patterns
    r = validate(base("    pattern: a\n    pattern-regex: b\n").sub("ERROR", "FATAL"))
    assert_match(/invalid severity/, messages(r))
    assert_match(/only one top-level pattern key/, messages(r))
  end

  def test_patterns_need_positive_term_and_single_key_items
    r = validate(base("    patterns:\n      - pattern-not: a\n      - pattern: b\n        pattern-not: c\n"))
    msg = messages(r)
    assert_match(/exactly one key/, msg)
    r2 = validate(base("    patterns:\n      - pattern-not: a\n"))
    assert_match(/positive term/, messages(r2))
  end

  def test_unknown_operator_and_metavariable_checks
    r = validate(base("    patterns:\n      - pattern: f($X)\n      - pattern-nott: g\n      - metavariable-regex:\n          metavariable: $Y\n          regex: a\n"))
    assert_match(/unknown operator: `pattern-nott`/, messages(r))
    assert_match(/\$Y is referenced/, messages(r, "warning"))
  end

  def test_taint_requires_sources_and_sinks
    r = validate(base("    mode: taint\n    pattern-sources:\n      - pattern: params\n"))
    assert_match(/pattern-sinks/, messages(r))
  end

  def test_floats_are_rejected
    r = validate(base("    pattern: a\n    metadata:\n      cvss: 9.8\n"))
    assert_match(/decimal numbers/, messages(r))
  end

  def test_duplicate_ids
    yaml = "rules:\n" + 2.times.map { "  - {id: dup, message: m, severity: INFO, languages: [ruby], pattern: a}\n" }.join
    assert_match(/duplicate id/, messages(validate(yaml)))
  end

  def test_yaml_syntax_error
    r = validate("rules:\n  - id: [\n")
    refute r.valid?
    assert_match(/invalid YAML/, messages(r))
  end

  def test_engine_validation
    eng = Trapline::Engine.detect
    skip "engine missing" unless eng
    r = Trapline::Validator.new(engine: eng).validate(base("    pattern: foo(\n"))
    refute r.valid?
    assert(r.issues.any? { |i| i.path == "engine" })
  end
end
