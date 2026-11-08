# frozen_string_literal: true

require "fileutils"

module Trapline
  class Store
    SLUG = %r{\A[A-Za-z0-9][A-Za-z0-9._\-/]*\z}
    RULE_EXT = %w[.yaml .yml].freeze

    attr_reader :root

    def initialize(root = Trapline.config.rules_path)
      @root = File.expand_path(root.to_s)
    end

    def list
      Dir.glob(File.join(root, "**", "*.{yaml,yml}")).sort.map { |path| summary(slug_for(path), path) }
    end

    def exists?(slug)
      !rule_path(slug).nil?
    end

    def read(slug)
      path = rule_path(slug) || raise(NotFound, "rule not found: #{slug}")
      test = test_path(slug)
      yaml = File.read(path)
      { slug: slug, yaml: yaml, test_code: test && File.read(test), test_language: test && test_language(test, yaml),
        updated_at: File.mtime(path).utc.iso8601 }
    end

    def write(slug, yaml, test_code: nil, language: nil)
      check_slug!(slug)
      path = rule_path(slug) || File.join(root, "#{slug}.yaml")
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, yaml.end_with?("\n") ? yaml : "#{yaml}\n")

      unless test_code.to_s.strip.empty?
        ext = Languages.extension_for(language || safe_language(yaml))
        test_file = File.join(File.dirname(path), "#{File.basename(slug)}.#{ext}")
        (test_paths(slug) - [test_file]).each { |p| File.delete(p) }
        File.write(test_file, test_code)
      end
      read(slug)
    end

    def delete(slug)
      path = rule_path(slug) || raise(NotFound, "rule not found: #{slug}")
      File.delete(path)
      test_paths(slug).each { |p| File.delete(p) }
      true
    end

    # Registry-style ids are named after their last segment, like the
    # semgrep/opengrep rules repos.
    def suggest_slug(id)
      name = id.to_s.split(".").reject(&:empty?).last.to_s
      base = name.downcase.gsub(%r{[^a-z0-9_/-]+}, "-").gsub(%r{\A[-/]+|[-/]+\z}, "")
      base = "rule" if base.empty?
      (1..).lazy.map { |n| n == 1 ? base : "#{base}-#{n}" }.find { |slug| !exists?(slug) }
    end

    private

    def summary(slug, path)
      rule = RuleFile.parse(File.read(path)).rules.first
      meta = rule&.data&.dig("metadata") || {}
      { slug: slug, id: rule&.id, message: rule&.message.to_s.lines.first.to_s.strip,
        severity: rule&.severity, languages: Array(rule&.languages),
        cve: Array(meta["cve"]), cwe: Array(meta["cwe"]), has_test: !test_path(slug).nil?,
        updated_at: File.mtime(path).utc.iso8601 }
    rescue ParseError => e
      { slug: slug, id: nil, error: e.message, updated_at: File.mtime(path).utc.iso8601 }
    end

    def slug_for(path)
      path.delete_prefix("#{root}/").sub(/\.ya?ml\z/, "")
    end

    def check_slug!(slug)
      raise InvalidSlug, "invalid name: #{slug.inspect}" unless slug.to_s.match?(SLUG) && !slug.include?("..")
    end

    def rule_path(slug)
      check_slug!(slug)
      RULE_EXT.map { |e| File.join(root, "#{slug}#{e}") }.find { |p| File.file?(p) }
    end

    def test_paths(slug)
      check_slug!(slug)
      Dir.glob(File.join(root, "#{slug}.*")).reject { |p| RULE_EXT.include?(File.extname(p)) || p.end_with?(".fixed") }
    end

    def test_path(slug)
      test_paths(slug).first
    end

    # generic and regex share .txt: the rule's own language wins.
    def test_language(test, yaml)
      ext = File.extname(test).delete_prefix(".").downcase
      own = Languages.find(safe_language(yaml))
      return own.key if own&.extension == ext

      Languages.from_extension(ext)&.key
    end

    def safe_language(yaml)
      RuleFile.parse(yaml).rules.first&.primary_language
    rescue ParseError
      nil
    end
  end
end
