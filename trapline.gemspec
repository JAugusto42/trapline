# frozen_string_literal: true

require_relative "lib/trapline/version"

Gem::Specification.new do |spec|
  spec.name = "trapline"
  spec.version = Trapline::VERSION
  spec.authors = ["Jose Augusto"]
  spec.email = ["joseaugusto.881@outlook.com"]
  spec.summary = "Editor and generator for semgrep/opengrep rules, standalone or mounted in Rails"
  spec.description = <<~DESC
    Trapline is a web editor for creating, testing and maintaining semgrep/opengrep
    rules, with structural validation, execution with ruleid/ok annotations and a
    draft generator from CVEs (NVD + OSV) with per-CWE templates. It works as a
    CLI (`trapline server`), as a Rack app and mounted in a Rails app.
  DESC
  spec.homepage = "https://github.com/JAugusto42/trapline"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.files = Dir["lib/**/*", "exe/*", "README.md", "LICENSE", "config.ru.example"]
  spec.bindir = "exe"
  spec.executables = ["trapline"]
  spec.require_paths = ["lib"]

  # No required dependencies: the editor runs with a built-in HTTP server.
  # When `rackup` + `puma`/`webrick` are installed, `trapline server` uses them.
  spec.add_development_dependency "minitest", ">= 5.0", "< 7"
  spec.add_development_dependency "rake", "~> 13.0"

  spec.requirements << "opengrep or semgrep on PATH to run rules"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"
end
