# frozen_string_literal: true

require "test_helper"
require "json"

class TestStoreAndApp < Minitest::Test
  include EngineHelper

  def setup
    @dir = Dir.mktmpdir("trapline-test")
    Trapline.reset_config!
    Trapline.config.rules_path = @dir
    @store = Trapline::Store.new(@dir)
  end

  def teardown
    FileUtils.rm_rf(@dir)
    Trapline.reset_config!
  end

  def rule_yaml(id = "demo")
    Trapline::Templates.starter("search", language: "ruby", id: id)[:yaml]
  end

  def test_store_crud_in_semgrep_test_layout
    @store.write("web/demo", rule_yaml, test_code: "# ruleid: demo\ndangerous_call(1)\n")
    assert File.exist?(File.join(@dir, "web/demo.yaml"))
    assert File.exist?(File.join(@dir, "web/demo.rb"))
    entry = @store.list.first
    assert_equal "web/demo", entry[:slug]
    assert entry[:has_test]
    assert_equal "ruby", @store.read("web/demo")[:test_language]

    # changing the test language removes the old file
    @store.write("web/demo", rule_yaml, test_code: "x", language: "python")
    assert File.exist?(File.join(@dir, "web/demo.py"))
    refute File.exist?(File.join(@dir, "web/demo.rb"))

    assert_equal "web/demo-2", @store.suggest_slug("web/demo")
    assert_equal "cve-2026-1-custom", @store.suggest_slug("php.lang.security.cve-2026-1-custom")
    @store.delete("web/demo")
    assert_empty @store.list
  end

  def test_test_language_follows_the_rule_when_the_extension_is_shared
    yaml = "rules:\n- id: img\n  message: m\n  severity: LOW\n  languages: [regex]\n  pattern-regex: php:8\n"
    saved = @store.write("img", yaml, test_code: "# ruleid: img\nFROM php:8\n")
    assert_equal "regex", saved[:test_language]
    assert File.exist?(File.join(@dir, "img.txt"))
    generic = yaml.sub("[regex]", "[generic]").sub("pattern-regex: php:8", "pattern: php")
    assert_equal "generic", @store.write("gen", generic, test_code: "php\n")[:test_language]
  end

  def test_store_rejects_traversal
    %w[../x a/../../b /etc/passwd .hidden].each do |slug|
      assert_raises(Trapline::InvalidSlug, slug) { @store.write(slug, rule_yaml) }
    end
  end

  # ---- app ----

  def app(**opts)
    Trapline::Web::App.new(store: @store, **opts)
  end

  def req(method, path, body = nil, app: self.app, headers: {}, script_name: "")
    env = { "REQUEST_METHOD" => method, "PATH_INFO" => path, "SCRIPT_NAME" => script_name,
            "rack.input" => StringIO.new(body ? JSON.generate(body) : "") }
    env["HTTP_X_TRAPLINE"] = "1" unless method == "GET"
    status, hdrs, chunks = app.call(env.merge(headers))
    text = chunks.join
    data = hdrs["content-type"].to_s.include?("json") ? JSON.parse(text) : text
    [status, data, hdrs]
  end

  def test_index_uses_mount_point_as_base
    status, html, = req("GET", "/", script_name: "/trapline")
    assert_equal 200, status
    assert_includes html, '<base href="/trapline/">'
    status, js, hdrs = req("GET", "/assets/app.js")
    assert_equal 200, status
    assert_includes hdrs["content-type"], "javascript"
    assert_includes js, "Trapline"
    assert_equal 404, req("GET", "/assets/../trapline.rb").first
  end

  def test_csrf_header_required
    env = { "REQUEST_METHOD" => "POST", "PATH_INFO" => "/api/validate", "rack.input" => StringIO.new("{}") }
    assert_equal 403, app.call(env).first
  end

  def test_rules_api
    status, data, = req("PUT", "/api/rules/demo", { yaml: rule_yaml, test_code: "# ruleid: demo\ndangerous_call(1)\n" })
    assert_equal 200, status, data.inspect
    assert_equal "demo", data["slug"]
    _, list, = req("GET", "/api/rules")
    assert_equal ["demo"], list["rules"].map { |r| r["slug"] }
    _, one, = req("GET", "/api/rules/demo")
    assert_includes one["test_code"], "dangerous_call"
    assert_equal 422, req("PUT", "/api/rules/demo", { yaml: "rules: [" }).first
    assert_equal 422, req("GET", "/api/rules/..%2Fx").first
    assert_equal 200, req("DELETE", "/api/rules/demo").first
    assert_equal 404, req("GET", "/api/rules/demo").first
  end

  def test_validate_and_merge
    _, v, = req("POST", "/api/validate", { yaml: rule_yaml })
    assert v["valid"]
    assert_equal "demo", v["fields"]["id"]
    _, m, = req("POST", "/api/merge", { yaml: rule_yaml, fields: { severity: "ERROR", metadata: { cve: "CVE-2024-0001" } } })
    rule = Trapline::Rule.parse(m["yaml"])
    assert_equal "ERROR", rule.severity
    assert_equal ["CVE-2024-0001"], rule.metadata["cve"]
  end

  def test_read_only_and_basic_auth
    Trapline.config.read_only = true
    assert_equal 403, req("PUT", "/api/rules/demo", { yaml: rule_yaml }).first
    Trapline.config.read_only = false

    Trapline.config.authorize = %w[admin s3cret]
    assert_equal 401, req("GET", "/api/info").first
    ok = { "HTTP_AUTHORIZATION" => "Basic #{['admin:s3cret'].pack('m0')}" }
    assert_equal 200, req("GET", "/api/info", headers: ok).first
    Trapline.config.authorize = ->(env) { env["HTTP_X_ADMIN"] == "1" }
    assert_equal 403, req("GET", "/api/info").first
    assert_equal 200, req("GET", "/api/info", headers: { "HTTP_X_ADMIN" => "1" }).first
  end

  def test_misconfigured_authorize_denies_access
    ["admin:s3cret", %w[only-user], true].each do |bad|
      Trapline.config.authorize = bad
      assert_equal 403, req("GET", "/api/info").first, "authorize = #{bad.inspect} must deny"
    end
    Trapline.config.authorize = method(:allow_all)
    assert_equal 200, req("GET", "/api/info").first
  end

  def allow_all(_env) = true

  def test_cve_manual_endpoint
    _, data, = req("POST", "/api/cve/manual", { record: { id: "CVE-2099-1", cwes: "CWE-22", description: "path traversal" }, language: "go" })
    assert_equal "cwe:CWE-22:go", data["candidates"].first["key"]
  end

  def test_run_endpoint
    require_engine!
    _, data, = req("POST", "/api/run", { yaml: rule_yaml, code: "# ruleid: demo\ndangerous_call(1)\n", language: "ruby" })
    assert_equal 1, data["findings"].size
    assert_equal 1, data["annotations"]["passed"]
    _, bad, = req("POST", "/api/run", { yaml: "rules:\n- id: x\n", code: "" })
    refute_empty bad["errors"]
  end

  def test_suite
    require_engine!
    @store.write("good", rule_yaml("good"), test_code: "# ruleid: good\ndangerous_call(1)\n")
    @store.write("bad", rule_yaml("bad"), test_code: "# ok: bad\ndangerous_call(1)\n")
    @store.write("notest", rule_yaml("notest"))
    results = Trapline::Suite.new(store: @store, engine: engine).run.to_h { |r| [r.slug, r.status] }
    assert_equal({ "bad" => "fail", "good" => "pass", "notest" => "skipped" }, results)
  end
end
