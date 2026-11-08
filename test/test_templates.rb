# frozen_string_literal: true

require "test_helper"

# Ensures every CWE template is a valid rule and passes its own annotated
# test code. When you add a template, this test covers it.
class TestTemplates < Minitest::Test
  include EngineHelper
  parallelize_me!

  def test_templates_load
    refute_empty Trapline::Templates.all
    Trapline::Templates.all.each do |t|
      assert_match(/\ACWE-\d+\z/, t.cwe)
      refute_empty t.languages, t.cwe
      t.languages.each_value do |spec|
        assert spec["rule"] && spec["test"], "#{t.cwe} incomplete"
        assert_includes spec["test"], "ruleid: __RULE_ID__", "#{t.cwe} needs at least one ruleid"
      end
    end
  end

  def test_aliases_and_detection
    assert_equal "CWE-78", Trapline::Templates.for_cwe("CWE-77").cwe
    assert_equal "CWE-89", Trapline::Templates.for_cwe("89").cwe
    assert_equal "CWE-918", Trapline::Templates.detect("allows Server-Side Request Forgery via the url param").first.cwe
    assert_nil Trapline::Templates.for_cwe("CWE-99999")
  end

  Trapline::Templates.all.each do |tpl|
    tpl.languages.each_key do |lang|
      define_method("test_#{tpl.cwe.downcase.tr('-', '_')}_#{lang}") do
        require_engine!
        id = "t-#{tpl.cwe.downcase}-#{lang}"
        rule = Trapline::Rule.new({ "id" => id, "message" => tpl.message, "severity" => "ERROR",
                                     "languages" => [lang], "metadata" => { "cwe" => [tpl.label], "references" => ["x"] } }
                                   .merge(tpl.body(lang)))
        yaml = rule.to_yaml
        v = Trapline::Validator.new.validate(yaml)
        assert v.valid?, v.errors.map(&:message).inspect
        res = engine.run(yaml, code: tpl.test_code(lang, id), language: lang)
        assert res.ok?, res.errors.inspect
        failures = res.annotations[:results].select { |r| r[:status] == "fail" }.map { |r| r[:reason] }
        assert_empty failures, "#{tpl.cwe}/#{lang}"
      end
    end
  end

  STARTERS = %w[search patterns taint].product(%w[ruby python javascript]) +
             %w[java go typescript php csharp kotlin scala rust c cpp swift].map { |l| ["taint", l] }

  STARTERS.each do |kind, lang|
    define_method("test_starter_#{kind}_#{lang}") do
      require_engine!
      s = Trapline::Templates.starter(kind, language: lang, id: "s")
      res = engine.run(s[:yaml], code: s[:test_code], language: s[:language])
      assert res.ok?, "#{kind}/#{lang}: #{res.errors}"
      assert res.annotations_passed?, "#{kind}/#{lang}: #{res.annotations.inspect}"
    end
  end
end
