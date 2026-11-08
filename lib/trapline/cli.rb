# frozen_string_literal: true

require "optparse"
require "json"

module Trapline
  class CLI
    USAGE = <<~TXT
      Usage: trapline <command> [options]

      Commands:
        server              Opens the web editor (default: http://127.0.0.1:9292)
        validate FILE...    Validates rule files (--engine also uses opengrep/semgrep)
        test                Runs saved rules against their test files
        run RULE TARGET     Runs a rule against a source file
        cve ID              Generates rule drafts from a CVE/GHSA
        templates           Lists the available templates
        version             Shows the version and the detected engine

      Global options:
        -r, --rules DIR     Rules directory (default: ./rules or $TRAPLINE_RULES_PATH)
            --engine-bin B  Engine binary (opengrep, semgrep or a path)
    TXT

    TEST_LABELS = { "pass" => "ok   ", "fail" => "FAIL ", "error" => "ERROR", "skipped" => "no test",
                    "no-annotations" => "no annotations" }.freeze

    def self.start(argv = ARGV, out: $stdout, err: $stderr)
      new(out: out, err: err).run(argv.dup)
    end

    def initialize(out:, err:)
      @out = out
      @err = err
    end

    def run(argv)
      leading_globals(argv)
      command = argv.shift
      case command
      when "server", "s" then server(argv)
      when "validate", "v" then validate(argv)
      when "test", "t" then test(argv)
      when "run" then run_rule(argv)
      when "cve", "new" then cve(argv)
      when "templates" then list_templates
      when "version", "-v", "--version" then version
      when nil, "help", "-h", "--help" then @out.puts(USAGE) || 0
      else
        @err.puts "unknown command: #{command}\n\n#{USAGE}"
        1
      end
    rescue OptionParser::ParseError, Error => e
      @err.puts "error: #{e.message}"
      1
    end

    private

    def leading_globals(argv)
      leading = []
      while (arg = argv.first) && arg.start_with?("-r", "--rules", "--engine-bin")
        leading << argv.shift
        leading << argv.shift if %w[-r --rules --engine-bin].include?(arg)
      end
      OptionParser.new { |o| global(o) }.parse!(leading) if leading.any?
    end

    def global(opts)
      opts.on("-r", "--rules DIR") { |d| Trapline.config.rules_path = File.expand_path(d) }
      opts.on("--engine-bin BIN") do |b|
        Trapline.config.engine_binary = b
        Trapline.engine = nil
      end
    end

    def server(argv)
      host = "127.0.0.1"
      port = 9292
      OptionParser.new do |o|
        global(o)
        o.on("-p", "--port PORT", Integer) { |p| port = p }
        o.on("-b", "--host HOST") { |h| host = h }
        o.on("--read-only") { Trapline.config.read_only = true }
        o.on("--basic-auth USER:PASS") { |v| Trapline.config.authorize = v.split(":", 2) }
        o.on("--offline") { Trapline.config.allow_network = false }
      end.parse!(argv)

      require_relative "web/server"
      @err.puts "warning: no engine found (install opengrep or semgrep); structural validation only" unless Trapline.engine
      @out.puts "Rules in #{File.expand_path(Trapline.config.rules_path)}"
      Web::Server.start(Web::App.new, host: host, port: port, logger: @out)
      0
    end

    def validate(argv)
      use_engine = false
      json = false
      OptionParser.new do |o|
        global(o)
        o.on("--engine") { use_engine = true }
        o.on("--json") { json = true }
      end.parse!(argv)
      raise Error, "provide at least one file" if argv.empty?

      engine = use_engine ? (Trapline.engine || raise(Error, "no engine found")) : nil
      results = argv.to_h { |f| [f, Validator.new(engine: engine).validate(File.read(f))] }
      if json
        @out.puts JSON.pretty_generate(results.transform_values(&:to_h))
      else
        results.each do |file, r|
          @out.puts "#{r.valid? ? 'ok   ' : 'ERROR'} #{file}"
          r.issues.reject { |i| i.level == "info" }.each { |i| @out.puts "      #{i.level}: #{i.path}: #{i.message}" }
        end
      end
      results.values.all?(&:valid?) ? 0 : 1
    end

    def test(argv)
      OptionParser.new { |o| global(o) }.parse!(argv)
      Trapline.config.rules_path = File.expand_path(argv.first) if argv.first
      results = Suite.new.run
      @out.puts "no rules in #{Trapline.store.root}" if results.empty?
      results.each do |r|
        @out.puts "#{TEST_LABELS[r.status]} #{r.slug}#{" (#{r.passed}/#{r.total})" if r.total.positive?}"
        (r.errors + r.failures).each { |m| @out.puts "      #{m}" }
      end
      failed = results.count { |r| %w[fail error].include?(r.status) }
      @out.puts "\n#{results.size} rules, #{failed} with problems"
      failed.zero? ? 0 : 1
    end

    def run_rule(argv)
      json = false
      OptionParser.new do |o|
        global(o)
        o.on("--json") { json = true }
      end.parse!(argv)
      rule_file, target = argv
      raise Error, "usage: trapline run RULE.yaml TARGET" unless rule_file && target

      engine = Trapline.engine || raise(Error, "no engine found")
      lang = Languages.from_extension(File.extname(target))&.key
      res = engine.run(File.read(rule_file), code: File.read(target), language: lang)
      if json
        @out.puts JSON.pretty_generate(res.to_h)
      else
        res.errors.each { |e| @err.puts "error: #{e}" }
        res.findings.each { |f| @out.puts "#{target}:#{f.line}: [#{f.rule_id}] #{f.code.strip}" }
        if (a = res.annotations)
          @out.puts "annotations: #{a[:passed]}/#{a[:total]} ok"
          a[:results].select { |r| r[:status] == "fail" }.each { |r| @out.puts "  #{r[:reason]}" }
        end
      end
      res.ok? && res.annotations_passed? ? 0 : 1
    end

    def cve(argv)
      language = nil
      save = false
      pick = nil
      from_json = nil
      OptionParser.new do |o|
        global(o)
        o.on("-l", "--lang LANG") { |l| language = l }
        o.on("--save", "Saves the first candidate (or --pick) to the rules directory") { save = true }
        o.on("--pick N", Integer) { |n| pick = n }
        o.on("--osv-json FILE", "Uses a saved OSV JSON instead of the network") { |f| from_json = f }
      end.parse!(argv)

      gen = Generator.new
      result = if from_json
                 gen.analyze(Cve::Client.parse_osv(JSON.parse(File.read(from_json))), language: language)
               else
                 raise Error, "usage: trapline cve CVE-YYYY-NNNN [--lang ruby]" if argv.empty?

                 gen.from_cve(argv.first, language: language)
               end

      rec = result[:record]
      @out.puts "#{rec[:id]} #{rec[:severity]} #{rec[:cwes].join(', ')}"
      @out.puts "  #{rec[:summary] || rec[:description].to_s[0, 200]}"
      result[:notes].each { |n| @out.puts "  - #{n}" }
      @out.puts
      result[:candidates].each_with_index { |c, i| @out.puts "  [#{i + 1}] #{c[:title]} — #{c[:language]}" }

      index = (pick || 1) - 1
      chosen = (result[:candidates][index] unless index.negative?) || raise(Error, "no such candidate: #{pick}")
      if save
        store = Trapline.store
        slug = store.suggest_slug(Rule.parse(chosen[:yaml]).id)
        store.write(slug, chosen[:yaml], test_code: chosen[:test_code], language: chosen[:language])
        @out.puts "\nSaved to #{File.join(store.root, slug)}.yaml"
      else
        @out.puts "\n#{chosen[:yaml]}"
      end
      0
    end

    def list_templates
      Templates.all.each { |t| @out.puts "#{t.cwe.ljust(9)} #{t.title.ljust(45)} #{t.languages.keys.join(', ')}" }
      0
    end

    def version
      e = Trapline.engine
      @out.puts "trapline #{VERSION}"
      @out.puts e ? "engine: #{e.name} #{e.version} (#{e.binary})" : "engine: not found (install opengrep or semgrep)"
      0
    end
  end
end
