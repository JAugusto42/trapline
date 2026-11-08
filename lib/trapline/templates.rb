# frozen_string_literal: true

require "yaml"

module Trapline
  module Templates
    DIR = File.expand_path("templates/cwe", __dir__)

    CWE_ALIASES = {
      "CWE-77" => "CWE-78", "CWE-88" => "CWE-78",
      "CWE-80" => "CWE-79", "CWE-83" => "CWE-79", "CWE-87" => "CWE-79",
      "CWE-23" => "CWE-22", "CWE-35" => "CWE-22", "CWE-36" => "CWE-22", "CWE-73" => "CWE-22",
      "CWE-564" => "CWE-89", "CWE-943" => "CWE-89",
      "CWE-95" => "CWE-94", "CWE-1336" => "CWE-94", "CWE-96" => "CWE-94",
      "CWE-326" => "CWE-327", "CWE-328" => "CWE-327", "CWE-916" => "CWE-327",
      "CWE-259" => "CWE-798", "CWE-321" => "CWE-798",
      "CWE-776" => "CWE-611", "CWE-827" => "CWE-611",
      "CWE-1188" => "CWE-917"
    }.freeze

    Template = Struct.new(:cwe, :name, :title, :owasp, :keywords, :message, :languages, keyword_init: true) do
      def label
        "#{cwe}: #{name}"
      end

      def supports?(lang)
        languages.key?(lang.to_s)
      end

      def body(lang)
        YAML.safe_load(languages.fetch(lang.to_s)["rule"])
      end

      def test_code(lang, rule_id)
        languages.fetch(lang.to_s)["test"].gsub("__RULE_ID__", rule_id)
      end

      def summary
        { cwe: cwe, name: name, title: title, languages: languages.keys }
      end
    end

    STARTERS = {
      "search" => {
        title: "Simple search (pattern)",
        body: { "pattern" => "dangerous_call(...)" },
        test: {
          "ruby" => "# ruleid: __RULE_ID__\ndangerous_call(1)\n# ok: __RULE_ID__\nsafe_call(1)\n",
          "python" => "# ruleid: __RULE_ID__\ndangerous_call(1)\n# ok: __RULE_ID__\nsafe_call(1)\n",
          "javascript" => "// ruleid: __RULE_ID__\ndangerous_call(1);\n// ok: __RULE_ID__\nsafe_call(1);\n"
        }
      },
      "patterns" => {
        title: "Combination (patterns + pattern-not)",
        body: {
          "patterns" => [
            { "pattern" => "$OBJ.$METHOD($ARG)" },
            { "pattern-not" => "$OBJ.$METHOD(\"...\")" },
            { "metavariable-regex" => { "metavariable" => "$METHOD", "regex" => "^(eval|exec)$" } }
          ]
        },
        test: {
          "ruby" => "# ruleid: __RULE_ID__\nobj.eval(input)\n# ok: __RULE_ID__\nobj.eval(\"1 + 1\")\n",
          "python" => "# ruleid: __RULE_ID__\nobj.eval(data)\n# ok: __RULE_ID__\nobj.eval(\"1 + 1\")\n",
          "javascript" => "// ruleid: __RULE_ID__\nobj.eval(input);\n// ok: __RULE_ID__\nobj.eval(\"1 + 1\");\n"
        }
      },
      "taint" => {
        title: "Data flow (taint)",
        body: {
          "mode" => "taint",
          "pattern-sources" => [{ "pattern" => "user_input(...)" }],
          "pattern-sanitizers" => [{ "pattern" => "sanitize(...)" }],
          "pattern-sinks" => [{ "pattern" => "dangerous_sink(...)" }]
        },
        test: {
          "ruby" => "# ruleid: __RULE_ID__\ndangerous_sink(user_input(:q))\n# ok: __RULE_ID__\ndangerous_sink(sanitize(user_input(:q)))\n",
          "python" => "# ruleid: __RULE_ID__\ndangerous_sink(user_input(\"q\"))\n# ok: __RULE_ID__\ndangerous_sink(sanitize(user_input(\"q\")))\n",
          "javascript" => "// ruleid: __RULE_ID__\ndangerous_sink(user_input(\"q\"));\n// ok: __RULE_ID__\ndangerous_sink(sanitize(user_input(\"q\")));\n",
          "java" => "class Example {\n  void run() {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"));\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")));\n  }\n}\n",
          "go" => "package main\n\nfunc run() {\n\t// ruleid: __RULE_ID__\n\tdangerous_sink(user_input(\"q\"))\n\t// ok: __RULE_ID__\n\tdangerous_sink(sanitize(user_input(\"q\")))\n}\n",
          "typescript" => "// ruleid: __RULE_ID__\ndangerous_sink(user_input(\"q\"));\n// ok: __RULE_ID__\ndangerous_sink(sanitize(user_input(\"q\")));\n",
          "php" => "<?php\n// ruleid: __RULE_ID__\ndangerous_sink(user_input(\"q\"));\n// ok: __RULE_ID__\ndangerous_sink(sanitize(user_input(\"q\")));\n",
          "csharp" => "class Example {\n  void Run() {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"));\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")));\n  }\n}\n",
          "kotlin" => "fun run() {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"))\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")))\n}\n",
          "scala" => "object Example {\n  def run(): Unit = {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"))\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")))\n  }\n}\n",
          "rust" => "fn run() {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"));\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")));\n}\n",
          "c" => "void run(void) {\n  // ruleid: __RULE_ID__\n  dangerous_sink(user_input(\"q\"));\n  // ok: __RULE_ID__\n  dangerous_sink(sanitize(user_input(\"q\")));\n}\n",
          "cpp" => "void run() {\n  // ruleid: __RULE_ID__\n  dangerous_sink(user_input(\"q\"));\n  // ok: __RULE_ID__\n  dangerous_sink(sanitize(user_input(\"q\")));\n}\n",
          "swift" => "func run() {\n    // ruleid: __RULE_ID__\n    dangerous_sink(user_input(\"q\"))\n    // ok: __RULE_ID__\n    dangerous_sink(sanitize(user_input(\"q\")))\n}\n"
        }
      },
      "regex" => {
        title: "Regular expression (pattern-regex)",
        body: { "pattern-regex" => "(?i)todo:\\s*security" },
        test: { "generic" => "# ruleid: __RULE_ID__\n# TODO: security review this\n" }
      }
    }.freeze

    module_function

    def all
      @all ||= Dir.glob(File.join(DIR, "*.yml")).sort_by { |f| f[/\d+/].to_i }.map do |file|
        data = YAML.safe_load(File.read(file))
        Template.new(**data.transform_keys(&:to_sym).slice(*Template.members))
      end
    end

    def for_cwe(cwe)
      id = Cve::Record.normalize_cwe(cwe)
      id = CWE_ALIASES.fetch(id, id)
      all.find { |t| t.cwe == id }
    end

    def cwe_name(cwe)
      all.find { |t| t.cwe == cwe }&.label || cwe
    end

    def detect(text)
      text = text.to_s.downcase
      return [] if text.empty?

      all.map { |t| [t, Array(t.keywords).count { |k| keyword_regex(k).match?(text) }] }
         .select { |_, score| score.positive? }
         .sort_by { |_, score| -score }
         .map(&:first)
    end

    # Whole words ("eval" must not hit "retrieval"), except at edges that are
    # not word characters ("../").
    def keyword_regex(keyword)
      k = keyword.downcase
      Regexp.new("#{'\\b' if k.match?(/\A\w/)}#{Regexp.escape(k)}#{'\\b' if k.match?(/\w\z/)}")
    end

    def starter(kind, language: "ruby", id: "my-rule")
      spec = STARTERS.fetch(kind.to_s) { STARTERS["search"] }
      lang = language.to_s
      test = spec[:test][lang] || spec[:test]["generic"] || placeholder_test(lang)
      langs = kind.to_s == "regex" ? ["regex"] : [lang]
      rule = Rule.new({ "id" => id, "message" => "Describe the problem and how to fix it.", "severity" => "WARNING",
                        "languages" => langs, **spec[:body],
                        "metadata" => { "category" => "security", "confidence" => "MEDIUM" } })
      { yaml: rule.to_yaml, test_code: test.gsub("__RULE_ID__", id), language: langs.first }
    end

    def placeholder_test(lang)
      c = Languages.comment_for(lang)
      "#{c} Write an example of vulnerable code and a fixed one here.\n" \
        "#{c} Before the line that MUST produce a finding, add a comment with ruleid, a colon and the rule id;\n" \
        "#{c} before the one that must NOT, use ok instead of ruleid.\n"
    end

    def dependency(package, rule_id)
      lang = package.language
      name = package.name.to_s
      body, test = case lang
                   when "ruby" then ruby_dependency(name, rule_id)
                   when "python" then python_dependency(name, rule_id)
                   when "javascript" then js_dependency(name, rule_id)
                   when "java" then java_dependency(name, rule_id)
                   when "go" then go_dependency(name, rule_id)
                   end
      return nil unless body

      { body: body, test: test, language: lang }
    end

    def ruby_dependency(name, id)
      paths = [name, name.tr("-", "/")].uniq
      body = { "pattern-either" => paths.map { |p| { "pattern" => "require \"#{p}\"" } } +
                                   [{ "pattern" => "gem \"#{name}\", ..." }] }
      test = <<~RUBY
        # ruleid: #{id}
        gem "#{name}", "~> 1.0"
        # ruleid: #{id}
        require "#{paths.last}"
        # ok: #{id}
        require "json"
      RUBY
      [body, test]
    end

    PYTHON_IMPORTS = { "pyyaml" => "yaml", "pillow" => "PIL", "beautifulsoup4" => "bs4",
                       "scikit-learn" => "sklearn", "python-dateutil" => "dateutil",
                       "pyjwt" => "jwt", "pycryptodome" => "Crypto", "opencv-python" => "cv2" }.freeze

    def python_dependency(name, id)
      mod = PYTHON_IMPORTS.fetch(name.downcase) { name.downcase.tr("-", "_").tr(".", "_") }
      body = { "pattern-either" => [
        { "pattern" => "import #{mod}" },
        { "pattern" => "import #{mod}.$SUB" },
        { "pattern" => "from #{mod} import $X" },
        { "pattern" => "from #{mod}.$SUB import $X" }
      ] }
      test = <<~PY
        # ruleid: #{id}
        import #{mod}
        # ruleid: #{id}
        from #{mod} import something
        # ok: #{id}
        import json
      PY
      [body, test]
    end

    def js_dependency(name, id)
      re = "=~/^#{Regexp.escape(name).gsub('/', '\/')}(\\/.*)?$/"
      body = { "pattern-either" => [
        { "pattern" => "require(\"#{re}\")" },
        { "pattern" => "import $X from \"#{re}\"" },
        { "pattern" => "import * as $X from \"#{re}\"" },
        { "pattern" => "import {...} from \"#{re}\"" },
        { "pattern" => "import \"#{re}\"" }
      ] }
      test = <<~JS
        // ruleid: #{id}
        const lib = require("#{name}");
        // ruleid: #{id}
        import thing from "#{name}";
        // ok: #{id}
        const fs = require("fs");
      JS
      [body, test]
    end

    def java_dependency(name, id)
      group = name.split(":").first.to_s
      return nil if group.empty?

      body = { "pattern-regex" => "(?m)^\\s*import\\s+(static\\s+)?#{Regexp.escape(group)}\\." }
      test = <<~JAVA
        // ruleid: #{id}
        import #{group}.Example;
        // ok: #{id}
        import java.util.List;

        public class App {}
      JAVA
      [body, test]
    end

    def go_dependency(name, id)
      # A regex: `import "..."` patterns report the whole import block on its first line.
      body = { "pattern-regex" => "(?m)^\\s*(import\\s+)?([\\w.]+\\s+)?\"#{Regexp.escape(name)}(/[^\"]*)?\"\\s*$" }
      test = <<~GO
        package main

        import (
        	// ruleid: #{id}
        	"#{name}"
        	// ok: #{id}
        	"fmt"
        )

        func main() { fmt.Println(x) }
      GO
      [body, test]
    end
  end
end
