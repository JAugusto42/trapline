# frozen_string_literal: true

module Trapline
  module Runtime
    DOTNET = { name: "dotnet", images: %w[mcr.microsoft.com/dotnet/runtime mcr.microsoft.com/dotnet/aspnet] }.freeze
    RUNTIMES = {
      "php:php" => { name: "php", images: %w[php] },
      "python:python" => { name: "python", images: %w[python] },
      "python:cpython" => { name: "python", images: %w[python] },
      "nodejs:node.js" => { name: "node", images: %w[node] },
      "ruby-lang:ruby" => { name: "ruby", images: %w[ruby] },
      "golang:go" => { name: "golang", images: %w[golang] },
      "microsoft:.net" => DOTNET,
      "microsoft:.net_core" => DOTNET,
      "microsoft:asp.net_core" => { name: "aspnet", images: %w[mcr.microsoft.com/dotnet/aspnet] }
    }.freeze

    Interval = Struct.new(:low, :high) # [low, high); high nil = unbounded

    module_function

    def runtime_for(product)
      RUNTIMES[Cve.product_key(product)]
    end

    # CPE ranges as [major, minor, patch] intervals. Non-numeric versions
    # (8.2.0rc1, 2.7.x) are skipped.
    def intervals(ranges)
      Array(ranges).filter_map do |r|
        if r["exact"]
          v = parse(r["exact"]) or next
          next Interval.new(v, bump(v))
        end

        low = bound(r["start_including"], r["start_excluding"]) || ([0, 0, 0] unless r["start_including"] || r["start_excluding"])
        high = bound(r["end_excluding"], r["end_including"])
        next if low.nil? || ((r["end_excluding"] || r["end_including"]) && high.nil?)
        next if high && (low <=> high) >= 0

        Interval.new(low, high)
      end
    end

    # Half-open bound: `as_is` is used directly, `bumped` is moved one patch up.
    def bound(as_is, bumped)
      as_is ? parse(as_is) : bumped && bump(parse(bumped))
    end

    def parse(version)
      return nil unless version.to_s.match?(/\A\d+(\.\d+){0,2}\z/)

      parts = version.split(".").map(&:to_i)
      parts + [0] * (3 - parts.size)
    end

    def bump(v)
      v && [v[0], v[1], v[2] + 1]
    end

    def format(v)
      v.join(".")
    end

    # Partial tags (`8`, `8.1`) only match when every version under them is
    # affected: `php:7.4` is flagged, `php:8.2` is not when 8.2.35 fixed it.
    def version_regex(intervals)
      intervals.map { |i| range_regex(i.low, i.high) }.uniq.join("|")
    end

    def range_regex(low, high)
      n = low.size
      a = low[0]
      d = high&.first
      return int_range(a, d && d - 1) if n == 1
      return "#{a}\\.(?:#{range_regex(low.drop(1), high.drop(1))})" if d == a

      alts = []
      if low.drop(1).all?(&:zero?)
        first_full = a
      else
        alts << "#{a}\\.(?:#{range_regex(low.drop(1), nil)})"
        first_full = a + 1
      end
      last_full = d && d - 1
      if last_full.nil? || first_full <= last_full
        alts << "(?:#{int_range(first_full, last_full)})(?:\\.\\d+){0,#{n - 1}}"
      end
      alts << "#{d}\\.(?:#{range_regex([0] * (n - 1), high.drop(1))})" if d && !high.drop(1).all?(&:zero?)
      alts.join("|")
    end

    def int_range(lo, hi)
      return (lo..hi).to_a.join("|") if hi

      digits = lo.to_s.size
      [*(lo..(10**digits - 1)), "\\d{#{digits + 1},}"].join("|")
    end

    def image_rule(product, rule_id)
      rt = runtime_for(product) or return nil
      ivs = intervals(product["versions"])
      return nil if ivs.empty?

      fixed = ivs.filter_map { |i| i.high && format(i.high) }.uniq
      { name: rt[:name], images: rt[:images], body: { "pattern-regex" => image_regex(rt[:images], ivs) },
        test: test_code(rt[:images].first, ivs, rule_id), fixed: fixed }
    end

    # Matches `<image>:<tag>` as a whole token (not `myorg/php:8.1` nor
    # `php:8.1.2x`) and Helm's `repository: <image>` followed within a few
    # lines by `tag: <tag>`. The finding starts at the image name.
    def image_regex(images, ivs)
      name = images.map { |i| i.include?("/") ? Regexp.escape(i) : "(?:docker\\.io/)?(?:library/)?#{Regexp.escape(i)}" }
                   .join("|")
      tag = "(?:#{version_regex(ivs)})(?:-[\\w.-]+)?(?![\\w.-])"
      ref = "(?<![\\w./@-])(?:#{name}):#{tag}"
      helm = "repository:[ \\t]*[\"']?(?:#{name})[\"']?[ \\t]*\\r?\\n" \
             "(?:(?![ \\t]*(?:repository|tag):)[^\\n]*\\n){0,3}[ \\t]*tag:[ \\t]*[\"']?#{tag}"
      "#{ref}|#{helm}"
    end

    def test_code(image, ivs, rule_id)
      lines = []
      ivs.first(4).each do |i|
        lines << "# ruleid: #{rule_id}" << "FROM #{image}:#{format(vulnerable(i))}-alpine"
        lines << "# ok: #{rule_id}" << "FROM #{image}:#{format(i.high)}-alpine" if i.high
      end
      i = ivs.first
      v = format(vulnerable(i))
      lines << "" << "# docker-compose.yml, Kubernetes, CI" << "services:" << "  app:"
      lines << "    # ruleid: #{rule_id}" << "    image: #{image}:#{v}"
      lines << "    # ok: #{rule_id}" << "    image: myorg/#{image.split('/').last}:#{v}"
      lines << "containers:" << "  # ruleid: #{rule_id}" << "  - image: \"#{image}:#{v}\""
      lines << "  # ok: #{rule_id}" << "  - image: \"#{image}:#{format(i.high)}\"" if i.high
      lines << "" << "# Helm values.yaml" << "image:" << "  # ruleid: #{rule_id}" << "  repository: #{image}"
      lines << "  pullPolicy: IfNotPresent" << "  tag: \"#{v}\""
      if i.high
        lines << "sidecar:" << "  # ok: #{rule_id}" << "  repository: #{image}" << "  tag: \"#{format(i.high)}\""
      end
      "#{lines.join("\n")}\n"
    end

    def vulnerable(interval)
      high = interval.high
      high && high[2].positive? ? [*high[0, 2], high[2] - 1] : interval.low
    end
  end
end
