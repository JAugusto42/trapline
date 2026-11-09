# frozen_string_literal: true

require_relative "lib/trapline/version"

Gem::Specification.new do |spec|
  spec.name = "trapline"
  spec.version = Trapline::VERSION
  spec.authors = ["Jose Augusto"]
  spec.email = ["joseaugusto.881@outlook.com"]
  spec.summary = "Write, test and generate opengrep/semgrep rules: web editor, CLI and CVE-to-rule drafts"
  spec.description = <<~DESC
    Trapline is a web editor and CLI for writing and testing opengrep/semgrep rules,
    plus a generator that turns a CVE into rule drafts with test code. It runs
    standalone, as a Rack app or mounted in Rails. See the README for installation
    and usage: https://github.com/JAugusto42/trapline#readme
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
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/releases"
  spec.metadata["rubygems_mfa_required"] = "true"
end
