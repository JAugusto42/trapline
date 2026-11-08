# frozen_string_literal: true

module Trapline
  class Validator
    Issue = Struct.new(:level, :path, :message, keyword_init: true) do
      def to_h
        { level: level, path: path, message: message }
      end
    end

    Result = Struct.new(:issues, :rules, keyword_init: true) do
      def valid?
        errors.empty?
      end

      def errors
        issues.select { |i| i.level == "error" }
      end

      def to_h
        { valid: valid?, issues: issues.map(&:to_h) }
      end
    end

    FORMULA_KEYS = %w[pattern pattern-not pattern-inside pattern-not-inside pattern-either patterns
                      pattern-regex pattern-not-regex metavariable-regex metavariable-pattern
                      metavariable-comparison metavariable-type metavariable-analysis metavariable-name
                      focus-metavariable].freeze
    POSITIVE_KEYS = %w[pattern pattern-inside pattern-either patterns pattern-regex].freeze
    EITHER_KEYS = %w[pattern patterns pattern-either pattern-regex pattern-inside].freeze
    ID_FORMAT = /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/
    CVE_FORMAT = /\ACVE-\d{4}-\d{4,}\z/
    CWE_FORMAT = /\ACWE-\d+/

    def self.call(yaml_or_rules, engine: nil)
      new(engine: engine).validate(yaml_or_rules)
    end

    def initialize(engine: nil)
      @engine = engine
    end

    def validate(input)
      @issues = []
      rules = case input
              when Rule then [input]
              when RuleFile then input.rules
              when Array then input
              else
                begin
                  RuleFile.parse(input).rules
                rescue ParseError => e
                  add("error", "", e.message)
                  return Result.new(issues: @issues, rules: [])
                end
              end

      add("error", "rules", "the file contains no rules") if rules.empty?
      rules.each_with_index { |rule, i| check_rule(rule, "rules[#{i}]") }
      check_duplicates(rules)

      if @engine && @issues.none? { |i| i.level == "error" }
        @engine.validate(RuleFile.new(rules).to_yaml).each { |e| add("error", "engine", e) }
      end

      Result.new(issues: @issues, rules: rules)
    end

    private

    def add(level, path, message)
      @issues << Issue.new(level: level, path: path, message: message)
    end

    def check_rule(rule, path)
      d = rule.data
      mode = d["mode"] || "search"

      if blank?(d["id"])
        add("error", "#{path}.id", "`id` is required")
      elsif d["id"].to_s !~ ID_FORMAT
        add("error", "#{path}.id", "`id` may only contain letters, digits, '.', '_' or '-'")
      end

      add("error", "#{path}.message", "`message` is required") if blank?(d["message"]) && mode != "extract"

      if blank?(d["severity"])
        add("error", "#{path}.severity", "`severity` is required")
      elsif !Rule::SEVERITIES.include?(d["severity"].to_s)
        add("error", "#{path}.severity", "invalid severity: #{d['severity']} (use #{Rule::SEVERITIES.first(4).join(', ')}...)")
      end

      check_languages(d["languages"], "#{path}.languages")

      unless Rule::MODES.include?(mode)
        add("error", "#{path}.mode", "invalid mode: #{mode} (use #{Rule::MODES.join(', ')})")
      end

      case mode
      when "taint" then check_taint(d, path)
      when "search" then check_search(d, path)
      end

      check_metavariables(d, path)
      check_scalars(d, path)
      check_metadata(d["metadata"], "#{path}.metadata")
    end

    def check_languages(langs, path)
      if !langs.is_a?(Array) || langs.empty?
        add("error", path, "`languages` must be a non-empty list (e.g. [ruby])")
        return
      end
      langs.reject { |l| Languages.known?(l) }.each { |l| add("warning", path, "language unknown to Trapline: #{l}") }
    end

    def check_search(d, path)
      present = Rule::PATTERN_KEYS.select { |k| d.key?(k) } - ["taint"]
      if present.empty?
        add("error", path, "the rule needs one of these keys: pattern, patterns, pattern-either, pattern-regex or match")
      elsif present.size > 1
        add("error", path, "use only one top-level pattern key (found: #{present.join(', ')})")
      end

      check_value(d["pattern"], "#{path}.pattern") if d.key?("pattern")
      check_value(d["pattern-regex"], "#{path}.pattern-regex", regex: true) if d.key?("pattern-regex")
      check_patterns(d["patterns"], "#{path}.patterns") if d.key?("patterns")
      check_either(d["pattern-either"], "#{path}.pattern-either") if d.key?("pattern-either")
    end

    def check_taint(d, path)
      return if d.key?("taint") # new taint syntax: left to the engine

      %w[pattern-sources pattern-sinks].each do |key|
        list = d[key]
        if !list.is_a?(Array) || list.empty?
          add("error", "#{path}.#{key}", "taint rules need `#{key}` with at least one item")
          next
        end
        list.each_with_index { |item, i| check_taint_spec(item, "#{path}.#{key}[#{i}]") }
      end
      %w[pattern-sanitizers pattern-propagators].each do |key|
        Array(d[key]).each_with_index { |item, i| check_taint_spec(item, "#{path}.#{key}[#{i}]") }
      end
    end

    def check_taint_spec(item, path)
      unless item.is_a?(Hash)
        add("error", path, "each item must be a map (e.g. `- pattern: ...`)")
        return
      end
      formula = item.slice(*FORMULA_KEYS)
      if formula.empty?
        add("error", path, "item without a pattern (use pattern, patterns or pattern-either)")
      elsif formula.size == 1
        check_formula_item(formula, path)
      end
    end

    def check_patterns(list, path)
      unless list.is_a?(Array) && !list.empty?
        add("error", path, "`patterns` must be a non-empty list")
        return
      end
      list.each_with_index { |item, i| check_formula_item(item, "#{path}[#{i}]") }

      keys = list.select { |i| i.is_a?(Hash) }.flat_map(&:keys)
      if (keys & POSITIVE_KEYS).empty?
        add("error", path, "`patterns` needs at least one positive term (pattern, pattern-inside, pattern-either, pattern-regex)")
      end
    end

    def check_either(list, path)
      unless list.is_a?(Array) && !list.empty?
        add("error", path, "`pattern-either` must be a non-empty list")
        return
      end
      list.each_with_index do |item, i|
        p = "#{path}[#{i}]"
        unless item.is_a?(Hash) && item.size == 1
          add("error", p, "each pattern-either item must have exactly one key")
          next
        end
        key = item.keys.first
        unless EITHER_KEYS.include?(key)
          add("error", p, "`#{key}` is not allowed inside pattern-either (use #{EITHER_KEYS.join(', ')})")
          next
        end
        check_formula_item(item, p)
      end
    end

    def check_formula_item(item, path)
      unless item.is_a?(Hash)
        add("error", path, "each item must be a map (e.g. `- pattern: ...`)")
        return
      end
      if item.size != 1
        add("error", path, "each item must have exactly one key (found: #{item.keys.join(', ')}) — check the indentation")
        return
      end

      key, value = item.first
      case key
      when "pattern", "pattern-not", "pattern-inside", "pattern-not-inside"
        check_value(value, "#{path}.#{key}")
      when "pattern-regex", "pattern-not-regex"
        check_value(value, "#{path}.#{key}", regex: true)
      when "patterns" then check_patterns(value, "#{path}.patterns")
      when "pattern-either" then check_either(value, "#{path}.pattern-either")
      when "focus-metavariable"
        Array(value).each { |mv| check_mv_name(mv, "#{path}.focus-metavariable") }
      when "metavariable-regex"
        check_mv_hash(value, "#{path}.#{key}", required: %w[metavariable regex])
        check_value(value["regex"], "#{path}.#{key}.regex", regex: true) if value.is_a?(Hash) && value["regex"]
      when "metavariable-pattern"
        check_mv_hash(value, "#{path}.#{key}", required: %w[metavariable])
        if value.is_a?(Hash)
          inner = value.slice("pattern", "patterns", "pattern-either", "pattern-regex")
          add("error", "#{path}.#{key}", "metavariable-pattern needs pattern, patterns, pattern-either or pattern-regex") if inner.empty?
          check_patterns(value["patterns"], "#{path}.#{key}.patterns") if value["patterns"]
          check_either(value["pattern-either"], "#{path}.#{key}.pattern-either") if value["pattern-either"]
        end
      when "metavariable-comparison"
        check_mv_hash(value, "#{path}.#{key}", required: %w[comparison])
      when "metavariable-type", "metavariable-name"
        check_mv_hash(value, "#{path}.#{key}", required: %w[metavariable])
      when "metavariable-analysis"
        check_mv_hash(value, "#{path}.#{key}", required: %w[metavariable analyzer])
      else
        add("error", path, "unknown operator: `#{key}`")
      end
    end

    def check_mv_hash(value, path, required:)
      unless value.is_a?(Hash)
        add("error", path, "expected a map with #{required.join(', ')}")
        return
      end
      required.each { |k| add("error", "#{path}.#{k}", "`#{k}` is required") if blank?(value[k]) }
      check_mv_name(value["metavariable"], "#{path}.metavariable") if value["metavariable"]
    end

    def check_mv_name(name, path)
      add("error", path, "metavariables must start with $ and be UPPERCASE (e.g. $X)") unless name.to_s =~ /\A\$[A-Z_][A-Z0-9_]*\z/
    end

    def check_value(value, path, regex: false)
      unless value.is_a?(String) && !value.strip.empty?
        add("error", path, "the pattern must be a non-empty string")
        return
      end
      if regex
        begin
          Regexp.new(value)
        rescue RegexpError => e
          add("warning", path, "regex may be invalid (#{e.message}); the engine uses PCRE")
        end
      else
        check_balance(value, path)
      end
    end

    def check_balance(text, path)
      stripped = text.gsub(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/, "")
      pairs = { "(" => ")", "[" => "]", "{" => "}" }
      stack = []
      stripped.each_char do |c|
        if pairs.key?(c) then stack << c
        elsif pairs.value?(c)
          return add("warning", path, "unbalanced parentheses/brackets in the pattern") if stack.pop != pairs.key(c)
        end
      end
      add("warning", path, "unbalanced parentheses/brackets in the pattern") unless stack.empty?
    end

    def check_metavariables(d, path)
      text = collect_patterns(d).join("\n")
      used = text.scan(/\$(?:\.\.\.)?([A-Z_][A-Z0-9_]*)/).flatten.map { |n| "$#{n}" }.uniq
      referenced = []
      walk(d) do |h|
        referenced << h["metavariable"] if h["metavariable"]
        referenced.concat(Array(h["focus-metavariable"]))
      end
      (referenced.uniq - used).each do |mv|
        add("warning", path, "metavariable #{mv} is referenced but does not appear in any pattern")
      end
      msg = [d["message"], d["fix"]].compact.join(" ")
      msg.scan(/\$([A-Z_][A-Z0-9_]*)/).flatten.map { |n| "$#{n}" }.uniq.each do |mv|
        add("warning", "#{path}.message", "#{mv} is used in the message/fix but does not appear in the patterns") unless used.include?(mv)
      end
    end

    def collect_patterns(obj, out = [])
      case obj
      when Hash
        obj.each do |k, v|
          if %w[pattern pattern-inside pattern-not pattern-not-inside].include?(k) && v.is_a?(String)
            out << v
          elsif k == "pattern-regex" && v.is_a?(String)
            out << v.scan(/\(\?P<([A-Z_][A-Z0-9_]*)>/).flatten.map { |n| "$#{n}" }.join(" ")
          else
            collect_patterns(v, out)
          end
        end
      when Array then obj.each { |v| collect_patterns(v, out) }
      end
      out
    end

    def walk(obj, &block)
      case obj
      when Hash
        yield obj
        obj.each_value { |v| walk(v, &block) }
      when Array then obj.each { |v| walk(v, &block) }
      end
    end

    # semgrep (Python/ruamel) rejects floats anywhere in the rule.
    def check_scalars(obj, path)
      case obj
      when Hash then obj.each { |k, v| check_scalars(v, "#{path}.#{k}") }
      when Array then obj.each_with_index { |v, i| check_scalars(v, "#{path}[#{i}]") }
      when Float then add("error", path, "semgrep does not accept decimal numbers (#{obj}); quote it: \"#{obj}\"")
      end
    end

    def check_metadata(meta, path)
      if meta.nil?
        add("info", path, "add `metadata` (cwe, references, confidence) to make triage easier")
        return
      end
      unless meta.is_a?(Hash)
        add("error", path, "`metadata` must be a map")
        return
      end
      Array(meta["cve"]).each do |c|
        add("warning", "#{path}.cve", "unexpected CVE format: #{c} (e.g. CVE-2021-44228)") unless c.to_s =~ CVE_FORMAT
      end
      Array(meta["cwe"]).each do |c|
        add("warning", "#{path}.cwe", "unexpected CWE format: #{c} (e.g. \"CWE-89: SQL Injection\")") unless c.to_s =~ CWE_FORMAT
      end
      add("info", "#{path}.cwe", "specify the related CWE") if blank?(meta["cwe"])
      add("info", "#{path}.references", "include references (advisory, CVE, documentation)") if blank?(meta["references"])
      if meta["confidence"] && !%w[LOW MEDIUM HIGH].include?(meta["confidence"].to_s)
        add("warning", "#{path}.confidence", "confidence must be LOW, MEDIUM or HIGH")
      end
    end

    def check_duplicates(rules)
      rules.map(&:id).compact.tally.each { |id, n| add("error", "rules", "duplicate id: #{id}") if n > 1 }
    end

    def blank?(v)
      v.nil? || (v.respond_to?(:empty?) && v.empty?) || (v.is_a?(String) && v.strip.empty?)
    end
  end
end
