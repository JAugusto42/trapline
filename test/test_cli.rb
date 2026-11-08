# frozen_string_literal: true

require "test_helper"
require "trapline/cli"

class TestCli < Minitest::Test
  def cli(*args)
    out = StringIO.new
    err = StringIO.new
    code = Trapline::CLI.start(args, out: out, err: err)
    [code, out.string, err.string]
  end

  def teardown
    Trapline.reset_config!
  end

  def test_help_and_templates
    code, out, = cli("help")
    assert_equal 0, code
    assert_includes out, "trapline <command>"
    _, out, = cli("templates")
    assert_includes out, "CWE-89"
  end

  def test_validate_exit_codes
    Dir.mktmpdir do |d|
      good = File.join(d, "good.yaml")
      bad = File.join(d, "bad.yaml")
      File.write(good, Trapline::Templates.starter("search", id: "g")[:yaml])
      File.write(bad, "rules:\n- id: b\n")
      assert_equal 0, cli("validate", good).first
      code, out, = cli("validate", good, bad)
      assert_equal 1, code
      assert_includes out, "ERROR #{bad}"
    end
  end

  def test_cve_from_osv_json_saves
    Dir.mktmpdir do |d|
      code, out, = cli("cve", "--osv-json", File.join(FIXTURES, "osv-GHSA-jfh8-c2jp-5v3q.json"), "-r", d, "--save")
      assert_equal 0, code
      assert_includes out, "CVE-2021-44228"
      assert File.exist?(File.join(d, "cve-2021-44228-expression-language-jndi-lookup-injection.yaml"))
      assert File.exist?(File.join(d, "cve-2021-44228-expression-language-jndi-lookup-injection.java"))
    end
  end

  def test_global_options_before_the_command
    Dir.mktmpdir do |d|
      code, out, = cli("-r", d, "cve", "--osv-json", File.join(FIXTURES, "osv-GHSA-jfh8-c2jp-5v3q.json"), "--save")
      assert_equal 0, code, out
      assert_equal File.expand_path(d), Trapline.config.rules_path
      assert File.exist?(File.join(d, "cve-2021-44228-expression-language-jndi-lookup-injection.yaml"))
      assert_equal 1, cli("--rules=#{d}", "bogus").first
    end
  end
end
