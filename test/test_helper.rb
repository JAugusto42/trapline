# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "trapline"
require "minitest/autorun"
require "tmpdir"
require "stringio"

FIXTURES = File.expand_path("fixtures", __dir__)

# Engine-bound test classes call `parallelize_me!`: each run is a separate
# opengrep process, so they overlap well. Classes that change Trapline.config
# stay serial, and minitest runs those before the parallel ones.
module EngineHelper
  def engine
    @engine ||= Trapline::Engine.detect
  end

  def require_engine!
    skip "opengrep/semgrep not installed" unless engine
  end
end

# Fake HTTP client that reads responses from test/fixtures.
FIXTURE_HTTP = lambda do |url, _headers|
  name = url.include?("nvd.nist.gov") ? "nvd-#{url[/cveId=([^&]+)/, 1]}" : "osv-#{url.split('/').last}"
  path = File.join(FIXTURES, "#{name}.json")
  raise Trapline::Error, "HTTP 404" unless File.exist?(path)

  File.read(path)
end
