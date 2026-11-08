# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module Trapline
  module Cve
    class Client
      NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
      OSV_URL = "https://api.osv.dev/v1/vulns/"
      CVE_ID = /\ACVE-\d{4}-\d{4,}\z/
      ECOSYSTEM_ALIAS = /\A(?:GO|RUSTSEC)-\d{4}-\d+\z/
      GHSA_ID = /\AGHSA(-[23456789cfghjmpqrvwx]{4}){3}\z/i

      attr_reader :errors

      # timeout: per request. total_timeout: for the whole #fetch; requests
      # that would start after it are skipped.
      def initialize(nvd_api_key: Trapline.config.nvd_api_key, http: nil, timeout: 15,
                     total_timeout: Trapline.config.cve_timeout, clock: nil)
        @nvd_api_key = nvd_api_key
        @http = http || method(:http_get)
        @timeout = timeout
        @total_timeout = total_timeout
        @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        @errors = []
      end

      def timed_out?
        @timed_out || false
      end

      def fetch(id)
        id = normalize_id(id)
        @errors = []
        @deadline = @total_timeout && @clock.call + @total_timeout

        record = Record.new(id: id)
        record.merge!(fetch_nvd(id)) if id.match?(CVE_ID)
        osv = fetch_osv(id)
        record.merge!(osv)
        follow_osv_links(record, osv) if osv

        cve_alias = record.aliases.grep(CVE_ID).first
        if id.match?(GHSA_ID) && cve_alias
          record.promote_cve!
          record.merge!(fetch_nvd(cve_alias))
        end

        @timed_out = time_left&.<=(0) || false
        if record.sources.empty?
          within = @timed_out ? " within #{format('%g', @total_timeout)} s" : ""
          raise NetworkError, "could not fetch #{id}#{within}: #{errors.uniq.join('; ')}"
        end

        record.aliases -= [record.id]
        record
      end

      def fetch_nvd(id)
        headers = {}
        headers["apiKey"] = @nvd_api_key if @nvd_api_key
        body = request("#{NVD_URL}?cveId=#{URI.encode_www_form_component(id)}", headers)
        self.class.parse_nvd(JSON.parse(body))
      rescue StandardError => e
        @errors << "NVD: #{e.message}"
        nil
      end

      def fetch_osv(id)
        body = request("#{OSV_URL}#{URI.encode_www_form_component(id)}", {})
        self.class.parse_osv(JSON.parse(body))
      rescue StandardError => e
        @errors << "OSV: #{e.message}"
        nil
      end

      def self.parse_nvd(json)
        cve = json.dig("vulnerabilities", 0, "cve") || json["cve"] || json
        return nil unless cve.is_a?(Hash) && cve["id"]

        metrics = cve["metrics"] || {}
        cvss = %w[cvssMetricV40 cvssMetricV31 cvssMetricV30 cvssMetricV2].lazy.filter_map { |k| Array(metrics[k]).first }.first
        cvss_data = cvss&.dig("cvssData") || {}
        cwes = Array(cve["weaknesses"]).flat_map { |w| Array(w["description"]).map { |d| d["value"] } }
        Record.new(
          id: cve["id"], description: Array(cve["descriptions"]).find { |d| d["lang"] == "en" }&.dig("value"),
          cwes: cwes.grep(/\ACWE-\d+\z/).uniq,
          severity: cvss_data["baseSeverity"] || cvss&.dig("baseSeverity"),
          cvss_score: cvss_data["baseScore"], cvss_vector: cvss_data["vectorString"],
          published: cve["published"], references: Array(cve["references"]).filter_map { |r| r["url"] },
          products: nvd_products(cve), sources: ["nvd"]
        )
      end

      def self.nvd_products(cve)
        Array(cve["configurations"]).flat_map { |c| Array(c["nodes"]) }.flat_map { |n| Array(n["cpeMatch"]) }
                                    .select { |m| m["vulnerable"] }
                                    .filter_map { |m| cpe_product(m["criteria"])&.merge("versions" => [cpe_range(m)].compact) }
                                    .group_by { |p| p.values_at("vendor", "product") }
                                    .map do |(vendor, product), matches|
          { "vendor" => vendor, "product" => product, "versions" => matches.flat_map { |m| m["versions"] }.uniq }
        end
      end

      def self.parse_osv(json)
        return nil unless json.is_a?(Hash) && json["id"]

        packages = Array(json["affected"]).filter_map do |a|
          pkg = a["package"] || {}
          next if pkg["name"].to_s.empty?

          events = Array(a["ranges"]).flat_map { |r| Array(r["events"]) }
          fixed = events.filter_map { |e| e["fixed"] }.uniq
          Package.new(ecosystem: pkg["ecosystem"].to_s.split(":").first, name: pkg["name"],
                      introduced: events.filter_map { |e| e["introduced"] }.find { |v| v != "0" },
                      fixed: fixed.empty? ? nil : fixed.join(", "),
                      last_affected: events.filter_map { |e| e["last_affected"] }.first,
                      ranges: event_ranges(events))
        end
        sev = json.dig("database_specific", "severity")&.upcase
        Record.new(
          id: json["id"], aliases: Array(json["aliases"]), summary: json["summary"],
          description: json["details"], cwes: Array(json.dig("database_specific", "cwe_ids")),
          severity: sev == "MODERATE" ? "MEDIUM" : sev, published: json["published"],
          references: Array(json["references"]).filter_map { |r| r["url"] },
          packages: packages, related: Array(json["related"]), sources: ["osv"]
        )
      end

      def self.event_ranges(events)
        events.each_with_object([]) do |e, ranges|
          if e["introduced"]
            ranges << { "introduced" => e["introduced"] }
          elsif ranges.any? && (e["fixed"] || e["last_affected"])
            ranges.last.merge!(e.slice("fixed", "last_affected"))
          end
        end
      end

      def self.cpe_range(match)
        version = match["criteria"].to_s.split(":")[5]
        return { "exact" => version } unless ["*", "-", nil, ""].include?(version)

        { "start_including" => match["versionStartIncluding"], "start_excluding" => match["versionStartExcluding"],
          "end_including" => match["versionEndIncluding"], "end_excluding" => match["versionEndExcluding"] }.compact
          .then { |r| r.empty? ? nil : r }
      end

      def self.cpe_product(cpe)
        parts = cpe.to_s.split(":")
        return nil if parts.size < 5

        { "vendor" => parts[3], "product" => parts[4] }
      end

      private

      def normalize_id(id)
        id = id.to_s.strip.upcase
        id = "GHSA-#{id[5..].downcase}" if id.match?(GHSA_ID)
        return id if id.match?(CVE_ID) || id.match?(GHSA_ID)

        raise Error, "invalid identifier: #{id} (use CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx)"
      end

      # The OSV record of a CVE often has no packages: they are in the GHSA it
      # links to. Go and RustSec advisories may list packages the GHSA lacks.
      def follow_osv_links(record, osv)
        linked = osv.aliases + osv.related
        linked.grep(GHSA_ID).first(2).each { |ghsa| record.merge!(fetch_osv(ghsa)) } if osv.packages.empty?
        linked.grep(ECOSYSTEM_ALIAS).uniq.first(2).each { |alias_id| record.merge!(fetch_osv(alias_id)) }
      end

      def time_left
        @deadline && (@deadline - @clock.call)
      end

      def request(url, headers)
        left = time_left
        raise Error, "time limit reached, request skipped" if left && left <= 0

        @request_timeout = left ? [@timeout, left].min : @timeout
        @http.call(url, headers)
      end

      def http_get(url, headers)
        uri = URI(url)
        req = Net::HTTP::Get.new(uri)
        req["Accept"] = "application/json"
        req["User-Agent"] = "trapline/#{VERSION}"
        headers.each { |k, v| req[k] = v }
        t = @request_timeout
        res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                                                  open_timeout: t, read_timeout: t, write_timeout: t) { |h| h.request(req) }
        raise Error, "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)

        res.body
      end
    end
  end
end
