# frozen_string_literal: true

require "json"
require "open3"
require "tmpdir"

module Trapline
  class Engine
    CANDIDATES = %w[opengrep semgrep].freeze
    QUIET_ENV = { "SEMGREP_SEND_METRICS" => "off", "SEMGREP_ENABLE_VERSION_CHECK" => "0",
                  "OPENGREP_SEND_METRICS" => "off" }.freeze

    Finding = Struct.new(:rule_id, :line, :end_line, :col, :end_col, :message, :severity, :code,
                         :metavars, keyword_init: true) do
      def to_h
        super.compact
      end
    end

    RunResult = Struct.new(:findings, :errors, :annotations, :duration, :engine, keyword_init: true) do
      def ok?
        errors.empty?
      end

      def annotations_passed?
        annotations.nil? || annotations[:failed].zero?
      end

      def to_h
        { findings: findings.map(&:to_h), errors: errors, annotations: annotations,
          duration: duration, engine: engine }
      end
    end

    attr_reader :binary, :timeout

    def self.detect(preferred = nil)
      [preferred, *CANDIDATES].compact.uniq.each do |bin|
        path = executable?(bin) ? bin : which(bin)
        return new(path) if path
      end
      nil
    end

    def self.which(cmd)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).map { |dir| File.join(dir, cmd) }.find { |f| executable?(f) }
    end

    def self.executable?(path)
      File.executable?(path) && !File.directory?(path)
    end

    def initialize(binary, timeout: Trapline.config.engine_timeout)
      @binary = binary
      @timeout = timeout
    end

    def name
      File.basename(binary).include?("opengrep") ? "opengrep" : "semgrep"
    end

    def version
      @version ||= capture([binary, "--version"]).first.to_s.strip.lines.last.to_s.strip
    end

    def run(yaml, code:, language: nil)
      rules = begin
        RuleFile.parse(yaml).rules
      rescue ParseError
        []
      end
      language ||= rules.first&.primary_language
      rule_ids = rules.filter_map { |r| r.id&.to_s }
      ext = Languages.extension_for(language)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      json, errors = scan(yaml, ext == "dockerfile" ? "Dockerfile" : "target.#{ext}", code)
      findings = Array(json&.dig("results")).map { |r| build_finding(r, code, rule_ids) }
      RunResult.new(findings: findings, errors: errors, annotations: Annotations.evaluate(code, findings, rule_ids: rule_ids),
                    duration: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3),
                    engine: "#{name} #{version}")
    end

    def validate(yaml)
      scan(yaml, "empty.txt", "").last
    end

    private

    def scan(yaml, target_name, code)
      Dir.mktmpdir("trapline") do |dir|
        rule_path = File.join(dir, "rule.yaml")
        target = File.join(dir, target_name)
        File.write(rule_path, yaml)
        File.write(target, code)

        cmd = [binary, "scan", "--config", rule_path, "--json", "--disable-version-check", "--no-git-ignore"]
        cmd << "--metrics=off" if name == "semgrep"
        out, err, status = capture(cmd << target, chdir: dir)
        json = parse_json(out)
        [json, errors_from(json, err, status, dir)]
      end
    end

    def parse_json(text)
      JSON.parse(text.to_s)
    rescue JSON::ParserError
      nil
    end

    def errors_from(json, err, status, dir)
      if json
        Array(json["errors"]).reject { |e| e["level"] == "warn" }.map { |e| format_error(e, dir) }.uniq
      elsif status.nil?
        ["the engine exceeded the #{timeout}s timeout"]
      else
        detail = err.to_s.lines.map(&:strip).reject(&:empty?).last(3).join(" ")
        ["failed to run #{name} (exit #{status.exitstatus}): #{strip_tmpdir(detail, dir)}"]
      end
    end

    def format_error(e, dir)
      msg = strip_tmpdir((e["long_msg"] || e["message"] || e["short_msg"] || e).to_s, dir).strip
      line = e.dig("spans", 0, "start", "line")
      line ? "#{e['type']}: #{msg} (rule line #{line})" : [e["type"], msg].compact.join(": ")
    end

    # The engine prints the temp dir as given or resolved (macOS /var ->
    # /private/var), and also in dotted form inside rule ids.
    def strip_tmpdir(text, dir)
      paths = [File.realpath(dir), dir].uniq
      prefixes = paths.map { |p| "#{p}/" } + paths.map { |p| "#{p.delete_prefix('/').tr('/', '.')}." }
      prefixes.sort_by { |p| -p.length }.reduce(text) { |t, p| t.gsub(p, "") }
    end

    # check_id comes prefixed with the dotted config path, and rule ids may
    # contain dots themselves, so match the declared ids.
    def rule_id_for(check_id, rule_ids)
      rule_ids.select { |id| check_id == id || check_id.end_with?(".#{id}") }.max_by(&:length) ||
        check_id.split(".").last
    end

    def build_finding(r, code, rule_ids)
      start = r["start"] || {}
      finish = r["end"] || {}
      snippet = code.lines[(start["line"].to_i - 1)..(finish["line"].to_i - 1)].to_a.join.chomp
      metavars = (r.dig("extra", "metavars") || {}).transform_values { |v| v["abstract_content"] }
      Finding.new(rule_id: rule_id_for(r["check_id"].to_s, rule_ids), line: start["line"], end_line: finish["line"],
                  col: start["col"], end_col: finish["col"], message: r.dig("extra", "message"),
                  severity: r.dig("extra", "severity"), code: snippet, metavars: metavars.empty? ? nil : metavars)
    end

    def capture(cmd, chdir: Dir.pwd)
      Open3.popen3(QUIET_ENV, *cmd, chdir: chdir, pgroup: true) do |stdin, stdout, stderr, wait|
        stdin.close
        out_reader = Thread.new { stdout.read }
        err_reader = Thread.new { stderr.read }
        unless wait.join(timeout)
          begin
            Process.kill("KILL", -wait.pid)
          rescue Errno::ESRCH
            nil
          end
          return [nil, "timeout", nil]
        end
        [out_reader.value, err_reader.value, wait.value]
      end
    rescue Errno::ENOENT => e
      [nil, e.message, Struct.new(:exitstatus).new(127)]
    end
  end

  module Annotations
    PATTERN = %r{(?:#|//|/\*|<!--|--)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([A-Za-z0-9._\-, ]+)}

    module_function

    def parse(code)
      lines = code.lines
      lines.each_with_index.filter_map do |line, idx|
        m = line.match(PATTERN) or next
        target = own_line?(line, m) ? next_code_line(lines, idx) : idx + 1
        { kind: m[1], rule_ids: m[2].split(",").map(&:strip).reject(&:empty?), annotation_line: idx + 1, line: target }
      end
    end

    def own_line?(line, match)
      line[0...match.begin(0)].strip.empty?
    end

    # Stacked annotations all point to the first line after them.
    def next_code_line(lines, idx)
      j = idx + 1
      j += 1 while j < lines.size && (m = lines[j].match(PATTERN)) && own_line?(lines[j], m)
      j + 1
    end

    # Like `--test`, every id in a ruleid/ok/todoruleid annotation must be a
    # rule of the file (todook is exempt).
    ID_CHECKED = %w[ruleid ok todoruleid].freeze

    def evaluate(code, findings, rule_ids: [])
      anns = parse(code)
      return nil if anns.empty?

      hit = Hash.new { |h, k| h[k] = [] }
      findings.each { |f| hit[f.line] << f.rule_id }
      lines = code.lines
      results = anns.map do |a|
        unknown = ID_CHECKED.include?(a[:kind]) && rule_ids.any? ? a[:rule_ids] - rule_ids : []
        next check(a, lines[a[:line] - 1], hit[a[:line]]) if unknown.empty?

        a.merge(line: a[:annotation_line], status: "fail",
                reason: "`#{a[:kind]}` names a rule that is not in this file: #{unknown.join(', ')}")
      end

      covered = anns.select { |a| %w[ruleid todoruleid ok].include?(a[:kind]) }.map { |a| a[:line] }
      findings.reject { |f| covered.include?(f.line) }.each do |f|
        results << { kind: "unexpected", rule_ids: [f.rule_id], line: f.line, status: "fail",
                     reason: "unexpected match on line #{f.line} (the line is not marked as expected)" }
      end

      { total: results.size, passed: results.count { |r| r[:status] == "pass" },
        failed: results.count { |r| r[:status] == "fail" }, results: results }
    end

    def check(ann, target, hit_ids)
      # A blank or missing target would make `ok:` pass without testing anything.
      if target.nil? || target.strip.empty?
        return ann.merge(line: ann[:annotation_line], status: "fail",
                         reason: "`#{ann[:kind]}` annotation has no code below it (line #{ann[:line]} is " \
                                 "#{target.nil? ? 'past the end of the file' : 'blank'})")
      end

      found = ann[:rule_ids].any? { |id| hit_ids.include?(id) }
      case ann[:kind]
      when "ruleid" then found ? ann.merge(status: "pass") : ann.merge(status: "fail", reason: "false negative: expected a finding on line #{ann[:line]}")
      when "ok" then found ? ann.merge(status: "fail", reason: "false positive on line #{ann[:line]}") : ann.merge(status: "pass")
      else ann.merge(status: "todo")
      end
    end
  end
end
