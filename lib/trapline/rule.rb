# frozen_string_literal: true

require "yaml"

module Trapline
  class Rule
    SEVERITIES = %w[CRITICAL HIGH MEDIUM LOW INFO ERROR WARNING INVENTORY EXPERIMENT].freeze
    MODES = %w[search taint join extract].freeze
    PATTERN_KEYS = %w[pattern patterns pattern-either pattern-regex match taint].freeze

    KEY_ORDER = %w[id message severity languages mode options pattern patterns pattern-either
                   pattern-regex match pattern-sources pattern-propagators pattern-sanitizers
                   pattern-sinks paths fix fix-regex metadata].freeze
    LIST_METADATA = %w[cwe cve references owasp].freeze

    attr_reader :data

    def initialize(data = {})
      @data = stringify(data)
    end

    def self.parse(yaml)
      RuleFile.parse(yaml).rules.first || raise(ParseError, "no rule found")
    end

    %w[id message severity languages mode fix].each do |key|
      define_method(key) { @data[key] }
      define_method("#{key}=") { |v| @data[key] = v }
    end

    def metadata
      @data["metadata"] ||= {}
    end

    def taint?
      @data["mode"] == "taint"
    end

    def primary_language
      Array(languages).first
    end

    def [](key)
      @data[key.to_s]
    end

    def []=(key, value)
      @data[key.to_s] = value
    end

    def merge_fields(fields)
      fields = stringify(fields)
      %w[id message severity fix].each do |k|
        next unless fields.key?(k)

        v = fields[k].to_s
        v.strip.empty? ? @data.delete(k) : @data[k] = v
      end
      @data["languages"] = split_list(fields["languages"]) if fields.key?("languages")

      (fields["metadata"] || {}).each do |k, v|
        value = LIST_METADATA.include?(k) ? split_list(v) : v
        value.nil? || (value.respond_to?(:empty?) && value.empty?) ? metadata.delete(k) : metadata[k] = value
      end
      @data.delete("metadata") if metadata.empty?
      self
    end

    def to_h
      known = KEY_ORDER.select { |k| @data.key?(k) }.to_h { |k| [k, @data[k]] }
      known.merge(@data.except(*KEY_ORDER))
    end

    def to_yaml
      RuleFile.new([self]).to_yaml
    end

    private

    def split_list(value)
      case value
      when Array then value.map { |v| v.to_s.strip }.reject(&:empty?)
      when nil then []
      else value.to_s.split(/[,\n]/).map(&:strip).reject(&:empty?)
      end
    end

    def stringify(obj)
      case obj
      when Hash then obj.to_h { |k, v| [k.to_s, stringify(v)] }
      when Array then obj.map { |v| stringify(v) }
      else obj
      end
    end
  end

  class RuleFile
    attr_reader :rules

    def initialize(rules = [])
      @rules = rules
    end

    def self.parse(yaml)
      doc = begin
        YAML.safe_load(yaml.to_s, aliases: false)
      rescue Psych::SyntaxError => e
        raise ParseError.new("invalid YAML: #{e.problem} (line #{e.line}, column #{e.column})",
                             line: e.line, column: e.column)
      end

      list = case doc
             when Hash
               if doc.key?("rules") then doc["rules"]
               elsif doc.key?("id") then [doc]
               else raise ParseError, "the document must have a `rules:` key"
               end
             when Array then doc
             when nil then raise ParseError, "empty document"
             else raise ParseError, "the document must be a map with `rules:`"
             end
      raise ParseError, "`rules` must be a list" unless list.is_a?(Array)

      new(list.map { |r| r.is_a?(Hash) ? Rule.new(r) : raise(ParseError, "each item in `rules` must be a map") })
    end

    def to_yaml
      Yaml.dump({ "rules" => rules.map(&:to_h) })
    end
  end

  module Yaml
    module_function

    def dump(obj)
      ast = Psych::Visitors::YAMLTree.create
      ast << obj
      ast.tree.each do |node|
        next unless node.is_a?(Psych::Nodes::Scalar) && node.value.is_a?(String)

        if node.value.include?("\n") && node.value.lines.none? { |l| l.end_with?(" \n") }
          node.style = Psych::Nodes::Scalar::LITERAL
          node.plain = false
          node.quoted = true
        elsif node.style == Psych::Nodes::Scalar::DOUBLE_QUOTED && plain_safe?(node.value)
          # Psych quotes anything that starts with a symbol ($X, (...)); semgrep
          # patterns are more readable without quotes when YAML allows it.
          node.style = Psych::Nodes::Scalar::PLAIN
          node.plain = true
          node.quoted = false
        end
      end
      ast.tree.yaml(nil, line_width: -1).sub(/\A---\s*\n/, "")
    end

    def plain_safe?(value)
      return false if value.empty? || value.include?("\n") || value != value.strip
      return false if value.match?(/\A[-?:,\[\]{}#&*!|>'"%@`]/) || value.include?(": ") || value.include?(" #")

      YAML.safe_load("k: #{value}") == { "k" => value }
    rescue Psych::Exception
      false
    end
  end
end
