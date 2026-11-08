# frozen_string_literal: true

module Trapline
  class Generator
    # Too broad to pick a template from: the description may say more.
    GENERIC_CWES = %w[CWE-20 CWE-74 CWE-284 CWE-664 CWE-693 CWE-707].freeze
    # Bugs in native code, which no rule over application code can find.
    MEMORY_CWES = %w[CWE-119 CWE-120 CWE-121 CWE-122 CWE-125 CWE-131 CWE-190 CWE-191 CWE-401 CWE-415
                     CWE-416 CWE-457 CWE-476 CWE-680 CWE-787 CWE-824 CWE-908 CWE-1325].freeze

    Candidate = Struct.new(:key, :kind, :title, :language, :languages, :yaml, :test_code, :notes, keyword_init: true)

    def initialize(client: nil, offline: !Trapline.config.allow_network)
      @client = client || Cve::Client.new
      @offline = offline
    end

    def from_cve(id, language: nil)
      raise NetworkError, "network access disabled (TRAPLINE_OFFLINE=1); enter the CVE data manually" if @offline

      result = analyze(@client.fetch(id), language: language)
      if @client.respond_to?(:timed_out?) && @client.timed_out?
        result[:notes].unshift("The lookup hit its time limit (cve_timeout), so some requests were skipped or cut short: " \
                               "the data may be incomplete. Try again or fill in the missing fields.")
      end
      result
    end

    def analyze(record, language: nil)
      record = Cve::Record.from_h(record) if record.is_a?(Hash)
      record.promote_cve!
      language = Languages.find(language)&.key if language
      fallback = record.languages.first

      templates, how = matching_templates(record)
      notes = [how, memory_note(record), *language_notes(record, language, fallback)].compact
      candidates = templates.filter_map do |tpl|
        lang = pick_language(tpl, language, record) or next
        wanted = language || fallback
        if wanted && lang != wanted
          notes << "Template #{tpl.cwe} has no #{lang_name(wanted)} version yet; using #{lang_name(lang)}. " \
                   "Use the taint skeleton for #{lang_name(wanted)}."
        end
        from_template(record, tpl, lang)
      end
      candidates += record.runtime_products.filter_map { |product| from_runtime(record, product) }
      candidates += record.packages.filter_map do |pkg|
        next if pkg.language.nil? || pkg.runtime_product || (language && pkg.language != language)

        from_dependency(record, pkg)
      end
      candidates << starter(record, language || fallback || "ruby", templates.first)

      { record: record.to_h, candidates: candidates.uniq(&:key).map(&:to_h), notes: notes }
    end

    private

    def memory_note(record)
      memory = record.cwes & MEMORY_CWES
      return if memory.empty?

      where = record.product_names.first(3).join(", ")
      image = record.runtime_products.any? { |p| Runtime.image_rule(p, "x") }
      "#{memory.join(', ')}: memory-safety flaw in native code. " \
        "A rule over application code cannot detect the bug itself; check the installed versions#{" (#{where})" unless where.empty?} and upgrade. " \
        "#{'The container image draft flags affected runtime versions. ' if image}" \
        "Use the skeleton only to flag code paths that reach the vulnerable feature."
    end

    def language_notes(record, language, fallback)
      return [] if language
      return ["Could not detect the language (no affected packages or known products); using Ruby. Pick the language and generate again."] unless fallback
      return [] if record.languages.size < 2

      ["Affects several languages (#{record.languages.join(', ')}); drafts that need one use #{fallback}. " \
       "Pick another in Language to generate them for it."]
    end

    def matching_templates(record)
      ranked = Templates.detect([record.summary, record.description].join(" "))
      by_cwe = record.cwes.filter_map { |c| Templates.for_cwe(c) }.uniq
      by_cwe = by_cwe.sort_by { |t| [ranked.index(t) || ranked.size, by_cwe.index(t)] }
      return [by_cwe, "CWE reported by the source: #{record.cwes.join(', ')}."] if by_cwe.any?

      # "remote code execution" in a use-after-free advisory is the impact, not
      # a code injection: a specific CWE from the source beats a keyword guess.
      if (record.cwes - GENERIC_CWES).any?
        return [[], "There is no template for #{record.cwes.join(', ')} yet; no class guessed from the description " \
                    "because the source already names the weakness."]
      end

      detected = ranked.first(2)
      if detected.any?
        reported = record.cwes.empty? ? "CWE (not reported)" : record.cwes.join(", ")
        return [detected, "No template for #{reported}; class detected from the description: #{detected.map(&:cwe).join(', ')}."]
      end

      [[], record.cwes.empty? ? "The source reported no CWE and the description did not point to a known class." : "There is no template for #{record.cwes.join(', ')} yet."]
    end

    def pick_language(tpl, preferred, record)
      [preferred, *record.languages, "ruby", *tpl.languages.keys].compact.find { |l| tpl.supports?(l) }
    end

    def from_template(record, tpl, lang)
      id = rule_id(record, slugify(tpl.title), lang: lang)
      rule = Rule.new(base(record, id, lang, message: "#{record.id}: #{truncate(record.title, 180)}\n\n#{tpl.message.strip}",
                                             cwe: tpl.label, owasp: tpl.owasp, confidence: "MEDIUM").merge(tpl.body(lang)))
      notes = [
        "Generic #{tpl.title} template for #{lang_name(lang)}. Adjust sources/sinks to the affected component's APIs.",
        "The test code uses `ruleid:`/`ok:` annotations; add examples from the real vulnerable and fixed code."
      ]
      notes << "Templates also available in: #{(tpl.languages.keys - [lang]).join(', ')}." if tpl.languages.size > 1
      Candidate.new(key: "cwe:#{tpl.cwe}:#{lang}", kind: "cwe", title: "#{tpl.title} (#{tpl.cwe})",
                    language: lang, languages: tpl.languages.keys, yaml: rule.to_yaml,
                    test_code: tpl.test_code(lang, id), notes: notes)
    end

    def from_runtime(record, product)
      runtime = Runtime.runtime_for(product) or return nil
      name = runtime[:name]
      id = rule_id(record, "vulnerable-#{name}-image", lang: "regex", scope: name)
      rt = Runtime.image_rule(product, id) or return nil

      image = rt[:images].first
      rule = Rule.new(base(record, id, "regex",
                           message: "This image reference uses a #{name} version affected by #{record.id}: " \
                                    "#{short_title(record)}.#{upgrade_hint(rt[:fixed], 'No fixed version reported yet.')}",
                           cwe: all_cwes(record), confidence: "HIGH").merge(rt[:body]))
      rule.metadata["affected"] = [{ "image" => rt[:images].join(", "), "fixed" => rt[:fixed] }.reject { |_, v| v.empty? }]
      notes = [
        "Flags references to #{rt[:images].map { |i| "`#{i}:<tag>`" }.join(' and ')} whose version is in the ranges reported by NVD: " \
        "Dockerfile `FROM`, `image:` in Compose, Kubernetes and CI files, Helm `repository:` + `tag:`, `docker run`. " \
        "It runs on every file; to narrow it, add `paths: include:` (e.g. Dockerfile, *.yml, *.yaml).",
        "Floating tags (#{floating_example(image, rt[:fixed])}, #{image}:latest) are only flagged when the whole line is affected: they move to the latest patch on rebuild. " \
        "Tags set through variables (`${PHP_VERSION}`, Helm templates) are not resolved.",
        "Covers only the official image. Built images, other base images and OS packages need an image scanner: " \
        "Trivy (`trivy image`), Grype or osv-scanner (`osv-scanner scan image`)."
      ]
      if %w[dotnet aspnet].include?(name)
        notes << "The SDK image (mcr.microsoft.com/dotnet/sdk) is not covered: its tags use SDK version numbers (8.0.404), not the runtime's."
      end
      Candidate.new(key: "runtime:#{name}", kind: "runtime", title: "Vulnerable #{name} version in container images",
                    language: "regex", languages: ["regex"], yaml: rule.to_yaml, test_code: rt[:test], notes: notes)
    end

    def floating_example(image, fixed)
      v = fixed.first
      v ? "#{image}:#{v.split('.').first(2).join('.')}" : "#{image}:<major>"
    end

    def from_dependency(record, pkg)
      pkg_slug = slugify(pkg.name.split(%r{[:/]}).last)
      id = rule_id(record, "#{pkg_slug}-usage", lang: pkg.language, scope: pkg_slug)
      dep = Templates.dependency(pkg, id) or return nil

      rule = Rule.new(base(record, id, dep[:language],
                           message: "This code uses #{pkg.name}, affected by #{record.id}: " \
                                    "#{short_title(record)}.#{upgrade_hint(Array(pkg.fixed))}",
                           cwe: all_cwes(record), confidence: "LOW").merge(dep[:body]))
      rule.metadata["affected"] = [{ "package" => pkg.name, "ecosystem" => pkg.ecosystem,
                                     "introduced" => pkg.introduced, "fixed" => pkg.fixed }.compact]
      notes = [
        "Finds imports/declarations of #{pkg.name} (#{pkg.ecosystem}). The rule does not check the installed version — pair it with an SCA tool (bundler-audit, npm audit, osv-scanner).",
        "Refine it with the specific vulnerable API (e.g. the method named in the advisory) to reduce noise."
      ]
      Candidate.new(key: "dependency:#{pkg.ecosystem}:#{pkg.name}", kind: "dependency",
                    title: "Usage of package #{pkg.name} (#{pkg.ecosystem})", language: dep[:language],
                    languages: [dep[:language]], yaml: rule.to_yaml, test_code: dep[:test], notes: notes)
    end

    def starter(record, lang, tpl)
      id = rule_id(record, "custom", lang: lang)
      skeleton = Templates.starter("taint", language: lang, id: id)
      rule = Rule.parse(skeleton[:yaml])
      rule.merge_fields("message" => "#{record.id}: #{truncate(record.title, 180)}")
      rule.data.merge!(base(record, id, lang, message: rule.message, cwe: all_cwes(record),
                                              owasp: tpl&.owasp, confidence: "LOW").slice("severity", "metadata"))
      Candidate.new(key: "starter:#{lang}", kind: "starter", title: "Taint skeleton (write from scratch)",
                    language: lang, languages: [lang], yaml: rule.to_yaml, test_code: skeleton[:test_code],
                    notes: ["Skeleton with the CVE metadata filled in. Define sources, sanitizers and sinks based on the advisory."])
    end

    def base(record, id, lang, message:, cwe: nil, owasp: nil, confidence: "MEDIUM")
      ids = [record.id, *record.aliases]
      nvd = ["https://nvd.nist.gov/vuln/detail/#{record.id}"] if record.id.to_s.start_with?("CVE-")
      meta = {
        "cve" => ids.grep(/\ACVE-/).uniq, "ghsa" => ids.grep(/\AGHSA-/).uniq,
        "cwe" => Array(cwe).compact, "owasp" => Array(owasp),
        "category" => "security", "subcategory" => ["vuln"], "confidence" => confidence,
        "likelihood" => "MEDIUM", "impact" => impact(record), "cvss_score" => record.cvss_score&.to_s,
        "references" => (Array(nvd) + record.references.first(4)).uniq, "source" => "trapline #{VERSION}"
      }.reject { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
      { "id" => id, "message" => message, "severity" => record.rule_severity, "languages" => [lang], "metadata" => meta }
    end

    def all_cwes(record)
      record.cwes.map { |c| Templates.cwe_name(c) }
    end

    def impact(record)
      { "CRITICAL" => "HIGH", "HIGH" => "HIGH", "LOW" => "LOW" }.fetch(record.severity.to_s, "MEDIUM")
    end

    def upgrade_hint(fixed, none = nil)
      return " #{none}".rstrip if fixed.empty?

      " Upgrade to #{fixed.join(', ')} or later."
    end

    # <language>.<framework, package or "lang">.security.<cve>-<suffix>
    def rule_id(record, suffix, lang:, scope: nil)
      name = [record.id.to_s.downcase, suffix].reject(&:empty?).join("-")
      scope = slugify(scope)
      [slugify(lang), scope.empty? ? "lang" : scope, "security", name].join(".")
    end

    def lang_name(key)
      Languages.find(key)&.name || key
    end

    def short_title(record)
      truncate(record.title, 160).delete_suffix(".")
    end

    def slugify(text)
      text.to_s.downcase.gsub(/\(.*?\)/, "").gsub(/[^a-z0-9]+/, "-").gsub(/\A-|-\z/, "")
    end

    def truncate(text, len)
      t = text.to_s.gsub(/\s+/, " ").strip
      t.length > len ? "#{t[0, len - 1].rstrip}…" : t
    end
  end
end
