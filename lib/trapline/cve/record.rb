# frozen_string_literal: true

module Trapline
  module Cve
    ECOSYSTEM_LANGUAGES = {
      "npm" => "javascript", "pypi" => "python", "rubygems" => "ruby", "maven" => "java",
      "go" => "go", "packagist" => "php", "nuget" => "csharp", "crates.io" => "rust",
      "hex" => "elixir", "pub" => "dart", "swifturl" => "swift", "cocoapods" => "swift"
    }.freeze

    PRODUCT_LANGUAGES = {
      "php:php" => "php", "python:python" => "python", "python:cpython" => "python",
      "nodejs:node.js" => "javascript", "ruby-lang:ruby" => "ruby", "golang:go" => "go",
      "oracle:jdk" => "java", "oracle:jre" => "java", "oracle:openjdk" => "java",
      "microsoft:.net" => "csharp", "microsoft:.net_core" => "csharp", "microsoft:asp.net_core" => "csharp",
      "rust-lang:rust" => "rust",
      "rubyonrails:rails" => "ruby", "rubyonrails:ruby_on_rails" => "ruby", "djangoproject:django" => "python",
      "palletsprojects:flask" => "python", "expressjs:express" => "javascript", "vmware:spring_framework" => "java",
      "laravel:framework" => "php", "wordpress:wordpress" => "php", "drupal:drupal" => "php",
      "symfony:symfony" => "php"
    }.freeze

    RUNTIME_PACKAGES = {
      "go/stdlib" => { "vendor" => "golang", "product" => "go" },
      "go/toolchain" => { "vendor" => "golang", "product" => "go" }
    }.freeze

    def self.product_key(product)
      "#{product['vendor']}:#{product['product']}"
    end

    Package = Struct.new(:ecosystem, :name, :introduced, :fixed, :last_affected, :ranges, keyword_init: true) do
      def language
        ECOSYSTEM_LANGUAGES[ecosystem.to_s.downcase]
      end

      def runtime_product
        RUNTIME_PACKAGES["#{ecosystem.to_s.downcase}/#{name}"]
      end

      # OSV ranges in the NVD CPE shape. Pre-release markers are dropped: Go
      # writes 1.22.0 as "1.22.0-0".
      def cpe_ranges
        Array(ranges).filter_map do |r|
          release = ->(v) { v&.sub(/-.*\z/, "") }
          range = { "start_including" => (release.(r["introduced"]) unless [nil, "", "0"].include?(r["introduced"])),
                    "end_excluding" => release.(r["fixed"]), "end_including" => release.(r["last_affected"]) }.compact
          range unless range.empty?
        end
      end

      def to_h
        super.except(:ranges).compact.merge(language: language).compact
      end
    end

    class Record
      attr_accessor :id, :aliases, :summary, :description, :cwes, :severity, :cvss_score,
                    :cvss_vector, :published, :references, :packages, :products, :sources, :related

      def initialize(**attrs)
        @aliases = []
        @cwes = []
        @references = []
        @packages = []
        @products = []
        @sources = []
        @related = []
        attrs.each { |k, v| public_send("#{k}=", v) }
      end

      def self.from_h(h)
        h = h.transform_keys(&:to_s)
        new(
          id: h["id"].to_s.strip.upcase,
          summary: h["summary"], description: h["description"],
          cwes: Array(h["cwes"] || h["cwe"]).flat_map { |c| c.to_s.split(/[,\s]+/) }.filter_map { |c| normalize_cwe(c) }.uniq,
          severity: h["severity"]&.to_s&.upcase, cvss_score: h["cvss_score"],
          references: Array(h["references"]).flat_map { |r| r.to_s.split(/\s+/) }.reject(&:empty?),
          packages: Array(h["packages"]).map { |p| p.is_a?(Package) ? p : Package.new(**p.transform_keys(&:to_sym).slice(*Package.members)) },
          products: Array(h["products"]).map { |p| p.transform_keys(&:to_s) },
          sources: ["manual"]
        )
      end

      def self.normalize_cwe(value)
        n = value.to_s[/\d+/]
        "CWE-#{n}" if n
      end

      def title
        summary.to_s.strip.empty? ? description.to_s.split(/(?<=\.)\s/).first.to_s : summary
      end

      def languages
        (packages.filter_map(&:language) + products.filter_map { |p| PRODUCT_LANGUAGES[Cve.product_key(p)] }).uniq
      end

      # NVD products plus the runtimes OSV lists as packages (Go's "stdlib").
      # NVD's version ranges win when it has them.
      def runtime_products
        with_versions = products.select { |p| Array(p["versions"]).any? }.map { |p| Cve.product_key(p) }
        from_packages = packages.filter_map { |p| p.runtime_product&.merge("versions" => p.cpe_ranges) }
                                .reject { |p| with_versions.include?(Cve.product_key(p)) }
                                .group_by { |p| Cve.product_key(p) }
                                .transform_values { |ps| ps.first.merge("versions" => ps.flat_map { |p| p["versions"] }.uniq) }
        products.reject { |p| from_packages.key?(Cve.product_key(p)) } + from_packages.values
      end

      # "vendor/product" names. Known runtimes/frameworks come first: the rest
      # are usually appliances that embed them.
      def product_names
        runtimes, others = products.partition { |p| PRODUCT_LANGUAGES.key?(Cve.product_key(p)) }
        (runtimes.any? ? runtimes : others).map { |p| p["vendor"] == p["product"] ? p["product"] : "#{p['vendor']}/#{p['product']}" }
      end

      def merge!(other)
        return self unless other

        self.id = other.id if id.to_s.empty?
        self.summary ||= other.summary
        self.description ||= other.description
        self.severity ||= other.severity
        self.cvss_score ||= other.cvss_score
        self.cvss_vector ||= other.cvss_vector
        self.published ||= other.published
        self.aliases = (aliases + other.aliases + [other.id]).compact.uniq - [id]
        self.cwes = (cwes + other.cwes).uniq
        self.references = (references + other.references).uniq
        self.products = (products + other.products).uniq
        self.sources = (sources + other.sources).uniq
        other.packages.each { |p| packages << p if packages.none? { |q| [q.ecosystem, q.name] == [p.ecosystem, p.name] } }
        self
      end

      def promote_cve!
        cve = aliases.grep(/\ACVE-\d{4}-\d+\z/).first
        return self unless id.to_s.start_with?("GHSA-") && cve

        self.aliases = (aliases - [cve] + [id]).uniq
        self.id = cve
        self
      end

      def rule_severity
        sev = severity.to_s.upcase
        %w[CRITICAL HIGH LOW].include?(sev) ? sev : "MEDIUM"
      end

      def to_h
        {
          id: id, aliases: aliases, summary: summary, description: description, cwes: cwes,
          severity: severity, cvss_score: cvss_score, cvss_vector: cvss_vector, published: published,
          references: references, packages: packages.map(&:to_h), products: products,
          languages: languages, sources: sources
        }
      end
    end
  end
end
