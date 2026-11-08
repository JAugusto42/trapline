# frozen_string_literal: true

require_relative "lib/trapline/version"

Gem::Specification.new do |spec|
  spec.name = "trapline"
  spec.version = Trapline::VERSION
  spec.authors = ["Jose Augusto"]
  spec.email = ["joseaugusto.881@outlook.com"]
  spec.summary = "Write, test and generate opengrep/semgrep rules: web editor, CLI and CVE-to-rule drafts"
  spec.description = <<~DESC
    Trapline is a web editor and CLI for writing and testing opengrep/semgrep
    rules, plus a generator that turns a CVE into rule drafts with test code.
    Test files stay in the standard --test format.

    INSTALL

      gem install trapline

    Trapline needs an engine on your PATH, opengrep (recommended) or semgrep:

      curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
      pip install semgrep

    The opengrep installer puts the binary in ~/.opengrep/cli/latest/. Add it to
    your PATH or pass --engine-bin. Check the setup with:

      trapline version

    USAGE

    Web editor (http://127.0.0.1:9292):

      trapline server -r ./rules

    Write the rule, paste vulnerable and fixed code, and click the margin to mark
    the lines that must or must not match. Trapline writes the ruleid/ok
    annotations and reruns as you type.

    Rule drafts from a CVE or GHSA (looked up in NVD and OSV):

      trapline cve CVE-2024-4577                           # list the drafts
      trapline cve CVE-2024-4577 --save --pick 2 -r ./rules

    Validate and test rules (exits 1 on failure, for CI):

      trapline validate --engine rules/*.yaml
      trapline test -r ./rules
      trapline run rules/my-rule.yaml app/models/user.rb

    Rails: add gem "trapline" to the Gemfile, then

      bin/rails generate trapline:install    # editor at /trapline
      bin/rails trapline:test

    It also runs as a Rack app (run Trapline::Web::App.new in config.ru). No
    runtime dependencies besides Ruby 3.3+ and the engine binary.
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
