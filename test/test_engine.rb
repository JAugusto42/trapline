# frozen_string_literal: true

require "test_helper"

class TestEngine < Minitest::Test
  include EngineHelper
  parallelize_me!

  RULE = <<~YAML
    rules:
      - id: no-eval
        message: eval of $X
        severity: ERROR
        languages: [ruby]
        pattern: eval($X)
  YAML

  def test_annotations_parse
    code = "# ruleid: a, b\nfoo\nbar # ok: a\n# todoruleid: a\nbaz\n"
    anns = Trapline::Annotations.parse(code)
    assert_equal [2, 3, 5], anns.map { |a| a[:line] }
    assert_equal %w[a b], anns.first[:rule_ids]
    assert_equal "todoruleid", anns.last[:kind]
  end

  def test_annotations_evaluate_without_engine
    code = "# ruleid: r\nbad\n# ok: r\ngood\nother\n"
    f = ->(line) { Trapline::Engine::Finding.new(rule_id: "r", line: line, end_line: line) }
    res = Trapline::Annotations.evaluate(code, [f.(2), f.(4), f.(5)])
    assert_equal 1, res[:passed]
    assert_equal 2, res[:failed]
    reasons = res[:results].map { |r| r[:reason] }.compact.join("\n")
    assert_match(/false positive on line 4/, reasons)
    assert_match(/unexpected match on line 5 /, reasons)
    assert_nil Trapline::Annotations.evaluate("x\n", [])
  end

  def test_registry_style_ids_with_dots
    require_engine!
    yaml = "rules:\n- id: ruby.lang.security.my-rule\n  message: m\n  severity: HIGH\n  languages: [ruby]\n  pattern: eval(...)\n"
    res = engine.run(yaml, code: "# ruleid: ruby.lang.security.my-rule\neval(x)\n# ok: ruby.lang.security.my-rule\nputs(x)\n")
    assert_equal ["ruby.lang.security.my-rule"], res.findings.map(&:rule_id)
    assert res.annotations_passed?, res.annotations.inspect
  end

  def test_annotation_without_code_below_fails
    f = ->(line) { Trapline::Engine::Finding.new(rule_id: "r", line: line, end_line: line) }

    # `ok:` as the last line: it used to pass vacuously on a line that does not exist.
    res = Trapline::Annotations.evaluate("# ruleid: r\nbad\n# ok: r\n", [f.(2)])
    assert_equal [1, 1], [res[:passed], res[:failed]]
    dangling = res[:results].find { |r| r[:status] == "fail" }
    assert_equal 3, dangling[:line]
    assert_match(/no code below it \(line 4 is past the end of the file\)/, dangling[:reason])

    # Followed by a blank line.
    res = Trapline::Annotations.evaluate("# ruleid: r\n\nbad\n", [f.(3)])
    reasons = res[:results].map { |r| r[:reason] }.compact.join("\n")
    assert_match(/line 2 is blank/, reasons)
    assert_match(/unexpected match on line 3 /, reasons)
  end

  def test_run_finds_and_scores
    require_engine!
    code = "# ruleid: no-eval\neval(params[:x])\n# ok: no-eval\nputs 1\n"
    res = engine.run(RULE, code: code, language: "ruby")
    assert res.ok?, res.errors.inspect
    assert_equal [2], res.findings.map(&:line)
    assert_equal "eval(params[:x])", res.findings.first.code
    assert_equal 2, res.annotations[:passed]
    assert res.annotations_passed?
  end

  def test_run_reports_rule_errors
    require_engine!
    res = engine.run(RULE.sub("eval($X)", "eval("), code: "eval(1)\n", language: "ruby")
    refute res.ok?
    refute_empty res.errors
  end

  def test_errors_do_not_leak_tmp_paths
    require_engine!
    tmp = [Dir.tmpdir, File.realpath(Dir.tmpdir)].uniq
    leaks = tmp + tmp.map { |t| t.delete_prefix("/").tr("/", ".") } + ["/var/folders", "/private/var", "/tmp/trapline"]
    # Invalid pattern: the engine embeds the path in the rule id ("var.folders...T.trapline...r").
    # Invalid YAML: the engine reports the config file path.
    [RULE.sub("eval($X)", "foo("), "rules: ["].each do |yaml|
      res = engine.run(yaml, code: "foo(1)\n", language: "ruby")
      refute_empty res.errors
      res.errors.each do |msg|
        leaks.each { |leak| refute_includes msg, leak }
        refute_match(/trapline\d{8}-/, msg)
      end
    end
  end

  def test_annotation_with_unknown_rule_id_fails_like_engine_test
    f = Trapline::Engine::Finding.new(rule_id: "no-eval", line: 2)
    code = "# ruleid: no-eval, other-rule\neval(x)\n# ok: other-rule\nputs 1\n# todook: other-rule\nputs 2\n"
    res = Trapline::Annotations.evaluate(code, [f], rule_ids: ["no-eval"])
    reasons = res[:results].map { |r| [r[:line], r[:status], r[:reason]] }
    assert_includes reasons, [1, "fail", "`ruleid` names a rule that is not in this file: other-rule"]
    assert_includes reasons, [3, "fail", "`ok` names a rule that is not in this file: other-rule"]
    assert_equal "todo", res[:results].last[:status]
    assert_equal 2, res[:failed]
    assert_equal 0, Trapline::Annotations.evaluate(code, [f])[:failed] # without ids, only the usual checks
  end
end
