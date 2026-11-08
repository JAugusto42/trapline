# frozen_string_literal: true

require_relative "lib/trapline/version"

Gem::Specification.new do |spec|
  spec.name = "trapline"
  spec.version = Trapline::VERSION
  spec.authors = ["Jose Augusto"]
  spec.email = ["joseaugusto.881@outlook.com"]
  spec.summary = "Write, test and generate opengrep/semgrep rules: web editor, CLI and CVE-to-rule drafts"
  spec.description = <<~DESC
    Trapline sets traps for vulnerable code: it takes you from a CVE to a tested
    opengrep/semgrep rule.

    The web editor validates the rule YAML as you type, runs it against test code
    and highlights each finding. You mark which lines must or must not match by
    clicking the margin or accepting results, and Trapline writes the ruleid/ok
    annotations for you, so the test file stays in the standard --test format
    that opengrep and semgrep read.

    Give it a CVE or GHSA id and it looks the advisory up in NVD and OSV, then
    drafts rules with test code: a template for the vulnerability class (CWE), a
    check for vulnerable runtime images (PHP, Python, Node.js, Ruby, Go, .NET) in
    Dockerfiles, Compose, Kubernetes, Helm and CI files, a rule that finds usage
    of the affected package, and a taint skeleton for 14 languages. Notes explain
    what was inferred and what still needs review.

    The CLI validates rules, runs their tests in CI and generates drafts. It runs
    standalone (trapline server), as a Rack app or mounted in Rails, with no
    runtime dependencies besides Ruby and the opengrep or semgrep binary.
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
