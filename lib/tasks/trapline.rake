# frozen_string_literal: true

namespace :trapline do
  desc "Runs all semgrep/opengrep rules against their test files"
  task test: :environment do
    require "trapline/cli"
    code = Trapline::CLI.start(["test"])
    exit(code) unless code.zero?
  end

  desc "Validates the structure of all rules"
  task validate: :environment do
    require "trapline/cli"
    files = Dir.glob(File.join(Trapline.config.rules_path, "**", "*.{yaml,yml}"))
    abort "no rules in #{Trapline.config.rules_path}" if files.empty?
    code = Trapline::CLI.start(["validate", *files])
    exit(code) unless code.zero?
  end
end
