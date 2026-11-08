# frozen_string_literal: true

require "test_helper"

class TestGenerator < Minitest::Test
  include EngineHelper
  parallelize_me!

  def generator
    Trapline::Generator.new(client: Trapline::Cve::Client.new(http: FIXTURE_HTTP), offline: false)
  end

  def test_nvd_and_osv_are_merged
    rec = Trapline::Cve::Client.new(http: FIXTURE_HTTP).fetch("cve-2021-44228")
    assert_equal "CVE-2021-44228", rec.id
    assert_equal "CRITICAL", rec.severity
    assert_equal 10.0, rec.cvss_score
    assert_includes rec.cwes, "CWE-917"
    assert_equal ["java"], rec.languages
    assert_equal %w[nvd osv], rec.sources
    assert_includes rec.aliases, "GHSA-jfh8-c2jp-5v3q"
    assert_equal({ "vendor" => "apache", "product" => "log4j", "versions" => [{ "start_including" => "2.0.1", "end_excluding" => "2.3.1" }] }, rec.products.first)
  end

  def test_log4shell_prefers_jndi_template
    result = generator.from_cve("CVE-2021-44228")
    keys = result[:candidates].map { |c| c[:key] }
    assert_equal "cwe:CWE-917:java", keys.first
    assert_includes keys, "dependency:Maven:org.apache.logging.log4j:log4j-core"
    assert_equal "starter:java", keys.last

    first = Trapline::Rule.parse(result[:candidates].first[:yaml])
    assert_equal "java.lang.security.cve-2021-44228-expression-language-jndi-lookup-injection", first.id
    dep = Trapline::Rule.parse(result[:candidates].find { |c| c[:kind] == "dependency" }[:yaml])
    assert_equal "java.log4j-core.security.cve-2021-44228-log4j-core-usage", dep.id
    assert_equal ["CVE-2021-44228"], first.metadata["cve"]
    assert_equal "10.0", first.metadata["cvss_score"]
    assert_equal "CRITICAL", first.severity
  end

  def test_ghsa_lookup_promotes_cve
    result = generator.from_cve("ghsa-6cvf-m58q-h9wf")
    assert_equal "CVE-2019-14234", result[:record][:id]
    assert_equal "cwe:CWE-89:python", result[:candidates].first[:key]
  end

  def test_language_override
    result = generator.from_cve("GHSA-6cvf-m58q-h9wf", language: "ruby")
    assert_equal "ruby", result[:candidates].first[:language]
    refute(result[:candidates].any? { |c| c[:kind] == "dependency" }) # package is PyPI
  end

  def test_manual_record_with_keyword_detection
    result = generator.analyze({ "id" => "CVE-2099-0001", "description" => "Allows OS command injection via the host field",
                                 "packages" => [{ "ecosystem" => "npm", "name" => "ping-wrapper", "fixed" => "2.0.0" }] })
    assert_equal "cwe:CWE-78:javascript", result[:candidates].first[:key]
    assert_match(/detected from the description/, result[:notes].join)
    dep = result[:candidates].find { |c| c[:kind] == "dependency" }
    assert_match(/Upgrade to 2.0.0/, dep[:yaml])
  end

  # CVE-2026-109618 (php2shell): memory corruption in the PHP interpreter, "RCE" as impact,
  # no OSV packages, only the NVD CPE php:php.
  def test_runtime_memory_bug_is_not_guessed_as_code_injection
    result = generator.analyze({
      "id" => "CVE-2026-109618", "severity" => "CRITICAL", "cwes" => "CWE-416, CWE-755, CWE-824",
      "description" => "PHP uses longjmp() for out-of-memory errors ... can lead to remote code execution (RCE).",
      "products" => [{ "vendor" => "php", "product" => "php" }, { "vendor" => "siemens", "product" => "energy_engage" }]
    })
    refute(result[:candidates].any? { |c| c[:kind] == "cwe" }, "must not guess CWE-94 from 'remote code execution'")
    starter = result[:candidates].first
    assert_equal "php", starter[:language]
    rule = Trapline::Rule.parse(starter[:yaml])
    assert_equal "CRITICAL", rule.severity
    assert_equal %w[CWE-416 CWE-755 CWE-824], rule.metadata["cwe"]
    assert_match(/<\?php/, starter[:test_code])
    notes = result[:notes].join("\n")
    assert_match(/source already names the weakness/, notes)
    assert_match(/memory-safety flaw in native code\. .*installed versions \(php\)/, notes)
    refute_match(/image draft/, notes) # no version ranges, so no runtime candidate
  end

  PHP_RANGES = [{ "start_including" => "7.3.0", "end_excluding" => "8.2.35" },
                { "start_including" => "8.3.0", "end_excluding" => "8.3.36" }].freeze

  def test_runtime_version_rule_for_image_references
    result = generator.analyze({
      "id" => "CVE-2026-109618", "severity" => "CRITICAL", "cwes" => "CWE-416", "description" => "PHP OOM bug.",
      "products" => [{ "vendor" => "php", "product" => "php", "versions" => PHP_RANGES }]
    })
    runtime = result[:candidates].first
    assert_equal "runtime:php", runtime[:key]
    assert_equal "regex", runtime[:language]
    rule = Trapline::Rule.parse(runtime[:yaml])
    assert_equal "regex.php.security.cve-2026-109618-vulnerable-php-image", rule.id
    assert_match(/Upgrade to 8\.2\.35, 8\.3\.36 or later\./, rule.message)
    assert_match(/Trivy/, runtime[:notes].join)
    assert_equal "php.lang.security.cve-2026-109618-custom", Trapline::Rule.parse(result[:candidates].last[:yaml]).id

    rx = Regexp.new(rule.to_h["pattern-regex"])
    vulnerable = %w[7.3.0 7.4 7.4.33 8.0 8.1.2-fpm 8.2.34 8.3.35-apache]
    safe = %w[7.2.34 8 8.2 8.2.35 8.3 8.3.36 8.4.0 latest]
    vulnerable.each { |t| assert_match rx, "FROM php:#{t}\n", t }
    safe.each { |t| refute_match rx, "FROM php:#{t}\n", t }
    [
      "FROM --platform=linux/amd64 docker.io/library/php:8.1.2-fpm AS base",
      "    image: \"php:7.4@sha256:abc\"", "  container: php:8.2.34", "docker run --rm php:8.1 php -v",
      "image:\n  repository: php\n  pullPolicy: IfNotPresent\n  tag: \"8.1.2\"\n"
    ].each { |code| assert_match rx, code, code }
    ["image: myorg/php:8.1", "image: php:8.2.35", "x = 'php:8.1.2x'",
     "repository: php\ntag: \"8.4\"\n", "repository: php\nrepository: node\ntag: 8.1\n"].each { |code| refute_match rx, code, code }

    require_engine!
    res = engine.run(runtime[:yaml], code: runtime[:test_code], language: "regex")
    assert res.annotations_passed?, res.annotations.inspect
  end

  def test_runtime_rule_for_dotnet_images
    result = generator.analyze({
      "id" => "CVE-2099-0100", "severity" => "HIGH", "cwes" => "CWE-400", "description" => ".NET denial of service.",
      "products" => [{ "vendor" => "microsoft", "product" => ".net",
                       "versions" => [{ "start_including" => "8.0.0", "end_excluding" => "8.0.11" }] }]
    })
    runtime = result[:candidates].find { |c| c[:kind] == "runtime" }
    assert_equal "runtime:dotnet", runtime[:key]
    rule = Trapline::Rule.parse(runtime[:yaml])
    assert_equal "regex.dotnet.security.cve-2099-0100-vulnerable-dotnet-image", rule.id
    rx = Regexp.new(rule.to_h["pattern-regex"])
    assert_match rx, "FROM mcr.microsoft.com/dotnet/aspnet:8.0.10-alpine"
    assert_match rx, "FROM mcr.microsoft.com/dotnet/runtime:8.0.3"
    refute_match rx, "FROM mcr.microsoft.com/dotnet/aspnet:8.0.11"
    refute_match rx, "FROM mcr.microsoft.com/dotnet/sdk:8.0.10"
    refute_match rx, "FROM aspnet:8.0.10"
    assert_match(/SDK image/, runtime[:notes].join)
    assert_equal "csharp", result[:candidates].last[:language]

    require_engine!
    res = engine.run(runtime[:yaml], code: runtime[:test_code], language: "regex")
    assert res.annotations_passed?, res.annotations.inspect
  end

  def test_cve_lookup_stops_at_total_time_limit
    now = 0.0
    timeouts = []
    client = nil
    http = lambda do |url, _headers|
      timeouts << client.instance_variable_get(:@request_timeout)
      now += 8 # every request takes 8 s
      case url
      when /nvd/ then raise Trapline::Error, "HTTP 503"
      when %r{vulns/CVE-2099-8888} then { "id" => "CVE-2099-8888", "aliases" => %w[GHSA-cfgh-jmpq-rvwx] }.to_json
      else raise "must be skipped: #{url}"
      end
    end
    client = Trapline::Cve::Client.new(http: http, timeout: 15, total_timeout: 10, clock: -> { now })
    rec = client.fetch("CVE-2099-8888")
    assert_equal ["osv"], rec.sources
    assert_equal [10, 2], timeouts # the second request only gets what is left
    assert(client.errors.any? { |e| e.include?("time limit reached") }, client.errors.inspect)
    assert client.timed_out?
    note = Trapline::Generator.new(client: client, offline: false).from_cve("CVE-2099-8888")[:notes].first
    assert_match(/hit its time limit/, note)

    now = 0.0
    timeouts.clear
    slow = Trapline::Cve::Client.new(http: ->(*) { now += 11; raise Trapline::Error, "timeout" },
                                     total_timeout: 10, clock: -> { now })
    error = assert_raises(Trapline::NetworkError) { slow.fetch("CVE-2099-8888") }
    assert_match(/within 10 s/, error.message)
  end

  def test_go_stdlib_package_becomes_golang_image_rule
    osv = { "id" => "GO-2099-0001", "aliases" => %w[CVE-2099-0200], "summary" => "net/http: too many headers",
            "affected" => [
              { "package" => { "ecosystem" => "Go", "name" => "stdlib" },
                "ranges" => [{ "type" => "SEMVER", "events" => [{ "introduced" => "0" }, { "fixed" => "1.21.9" },
                                                                 { "introduced" => "1.22.0-0" }, { "fixed" => "1.22.2" }] }] },
              { "package" => { "ecosystem" => "Go", "name" => "golang.org/x/net" },
                "ranges" => [{ "type" => "SEMVER", "events" => [{ "introduced" => "0" }, { "fixed" => "0.23.0" }] }] }
            ] }
    result = generator.analyze(Trapline::Cve::Client.parse_osv(osv))
    keys = result[:candidates].map { |c| c[:key] }
    assert_includes keys, "runtime:golang"
    refute(keys.any? { |k| k.include?("stdlib") }, keys.inspect)
    assert_includes keys, "dependency:Go:golang.org/x/net"
    runtime = result[:candidates].find { |c| c[:key] == "runtime:golang" }
    rule = Trapline::Rule.parse(runtime[:yaml])
    assert_match(/Upgrade to 1\.21\.9, 1\.22\.2 or later/, rule.message)
    rx = Regexp.new(rule.to_h["pattern-regex"])
    %w[1.20 1.21.8 1.22.1-alpine].each { |t| assert_match rx, "FROM golang:#{t}", t }
    %w[1.21.9 1.22 1.22.2 1.23].each { |t| refute_match rx, "FROM golang:#{t}", t }
  end

  def test_template_without_the_detected_language_is_explained
    result = generator.analyze({ "id" => "CVE-2099-0300", "cwes" => "CWE-78", "description" => "Command injection.",
                                 "products" => [{ "vendor" => "php", "product" => "php" }] })
    cwe = result[:candidates].find { |c| c[:kind] == "cwe" }
    assert_equal "ruby", cwe[:language]
    assert_match(/Template CWE-78 has no PHP version yet; using Ruby/, result[:notes].join)
    assert_equal "php", result[:candidates].last[:language]
  end

  def test_follows_go_alias_for_extra_packages
    osv = ->(id, pkgs, aliases) { { "id" => id, "aliases" => aliases, "affected" => pkgs.map { |e, n| { "package" => { "ecosystem" => e, "name" => n } } } }.to_json }
    http = lambda do |url, _headers|
      case url
      when /nvd/ then raise Trapline::Cve::Client::Error, "offline"
      when %r{vulns/CVE-2099-7777} then osv.("CVE-2099-7777", [%w[PyPI brotli]], %w[GO-2099-1 BIT-node-2099-7])
      when %r{vulns/GO-2099-1} then osv.("GO-2099-1", [%w[Go github.com/andybalholm/brotli]], %w[CVE-2099-7777])
      else raise "unexpected request: #{url}"
      end
    end
    rec = Trapline::Cve::Client.new(http: http).fetch("CVE-2099-7777")
    assert_equal %w[brotli github.com/andybalholm/brotli], rec.packages.map(&:name)
    assert_equal %w[python go], rec.languages
  end

  def test_severity_keeps_cvss_scale_and_unknown_language_is_reported
    { "HIGH" => "HIGH", "MODERATE" => "MEDIUM", "LOW" => "LOW", nil => "MEDIUM" }.each do |cve_sev, rule_sev|
      result = generator.analyze({ "id" => "CVE-2099-0002", "severity" => cve_sev, "description" => "Something odd." })
      assert_equal rule_sev, Trapline::Rule.parse(result[:candidates].first[:yaml]).severity
      assert_match(/Could not detect the language/, result[:notes].join)
    end
  end

  def test_keywords_match_whole_words
    assert_empty Trapline::Templates.detect("The retrieval describes provides")
    assert_equal "CWE-22", Trapline::Templates.detect("Path traversal via ../ sequences").first.cwe
  end

  def test_offline_mode
    assert_raises(Trapline::NetworkError) { Trapline::Generator.new(offline: true).from_cve("CVE-2021-44228") }
  end

  def test_every_candidate_runs_green
    require_engine!
    [["CVE-2021-44228", nil], ["GHSA-6cvf-m58q-h9wf", nil], ["GHSA-6cvf-m58q-h9wf", "go"]].each do |id, lang|
      generator.from_cve(id, language: lang)[:candidates].each do |c|
        v = Trapline::Validator.new.validate(c[:yaml])
        assert v.valid?, "#{c[:key]}: #{v.errors.map(&:message)}"
        res = engine.run(c[:yaml], code: c[:test_code], language: c[:language])
        assert res.ok?, "#{c[:key]}: #{res.errors}"
        assert res.annotations_passed?, "#{c[:key]}: #{res.annotations.inspect}"
      end
    end
  end

  def test_dependency_templates_per_ecosystem
    require_engine!
    { "RubyGems" => "nokogiri", "PyPI" => "PyYAML", "npm" => "lodash", "Maven" => "com.fasterxml.jackson.core:jackson-databind",
      "Go" => "github.com/gin-gonic/gin" }.each do |eco, name|
      pkg = Trapline::Cve::Package.new(ecosystem: eco, name: name)
      dep = Trapline::Templates.dependency(pkg, "dep")
      rule = Trapline::Rule.new({ "id" => "dep", "message" => "m", "severity" => "INFO", "languages" => [dep[:language]] }.merge(dep[:body]))
      res = engine.run(rule.to_yaml, code: dep[:test], language: dep[:language])
      assert res.ok?, "#{eco}: #{res.errors}"
      assert res.annotations_passed?, "#{eco}: #{res.annotations.inspect}"
    end
  end
end
