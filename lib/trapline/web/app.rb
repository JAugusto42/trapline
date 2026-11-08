# frozen_string_literal: true

require "json"
require "openssl"

module Trapline
  module Web
    class App
      ASSETS = File.expand_path("assets", __dir__)
      MIME = { ".js" => "application/javascript", ".css" => "text/css", ".html" => "text/html",
               ".svg" => "image/svg+xml", ".woff2" => "font/woff2", ".txt" => "text/plain" }.freeze
      MAX_BODY = 2 * 1024 * 1024
      CSRF_HEADER = "HTTP_X_TRAPLINE"

      class HttpError < StandardError
        attr_reader :status

        def initialize(status, message)
          super(message)
          @status = status
        end
      end

      def initialize(store: nil, engine: :auto, generator: nil, config: Trapline.config)
        @config = config
        @store = store
        @engine = engine
        @generator = generator
      end

      def call(env)
        authorize!(env)
        method = env["REQUEST_METHOD"]
        path = env["PATH_INFO"].to_s
        path = "/" if path.empty?

        if %w[POST PUT DELETE PATCH].include?(method) && env[CSRF_HEADER] != "1"
          raise HttpError.new(403, "missing X-Trapline header (CSRF protection)")
        end

        route(method, path, env)
      rescue HttpError => e
        json({ error: e.message }, e.status, e.status == 401 ? { "www-authenticate" => 'Basic realm="Trapline"' } : {})
      rescue NotFound => e
        json({ error: e.message }, 404)
      rescue InvalidSlug, ParseError => e
        json({ error: e.message }, 422)
      rescue NetworkError => e
        json({ error: e.message }, 502)
      rescue Error => e
        json({ error: e.message }, 400)
      end

      private

      def store
        @store ||= Store.new(@config.rules_path)
      end

      def engine
        @engine = Trapline.engine if @engine == :auto
        @engine
      end

      def slug_route(path)
        path[%r{\A/api/rules/(.+)\z}, 1]
      end

      def generator
        @generator ||= Generator.new
      end

      def route(method, path, env)
        case [method, path]
        in ["GET", "/"] then index(env)
        in ["GET", %r{\A/assets/([\w.-]+)\z}] then asset(Regexp.last_match(1))
        in ["GET", "/api/info"] then json(info)
        in ["GET", "/api/templates"] then json(templates)
        in ["POST", "/api/templates/new"]
          b = body(env)
          json(Templates.starter(b["kind"] || "search", language: b["language"] || "ruby",
                                                        id: b["id"].to_s.empty? ? "my-rule" : b["id"]))
        in ["GET", "/api/rules"] then json(rules: store.list, path: store.root, read_only: @config.read_only)
        in ["GET", %r{\A/api/rules/.+\z}] then json(store.read(slug_route(path)))
        in ["PUT", %r{\A/api/rules/.+\z}] then save(slug_route(path), body(env))
        in ["DELETE", %r{\A/api/rules/.+\z}] then destroy(slug_route(path))
        in ["POST", "/api/validate"] then validate(body(env))
        in ["POST", "/api/run"] then run(body(env))
        in ["POST", "/api/merge"] then merge(body(env))
        in ["POST", "/api/cve"]
          b = body(env)
          json(generator.from_cve(b["id"].to_s, language: presence(b["language"])))
        in ["POST", "/api/cve/manual"]
          b = body(env)
          json(generator.analyze(Cve::Record.from_h(b["record"] || {}), language: presence(b["language"])))
        else
          raise HttpError.new(404, "route not found: #{method} #{path}")
        end
      end

      def index(env)
        base = "#{env['SCRIPT_NAME']}/".squeeze("/")
        html = File.read(File.join(ASSETS, "index.html")).sub("__BASE__", base)
        [200, { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-cache" }, [html]]
      end

      def asset(name)
        file = File.join(ASSETS, name)
        raise HttpError.new(404, "asset not found") unless File.file?(file)

        type = MIME.fetch(File.extname(name), "application/octet-stream")
        type += "; charset=utf-8" if type.start_with?("text/", "application/javascript")
        cache = name.end_with?(".woff2") || name.start_with?("codemirror") ? "public, max-age=86400" : "no-cache"
        [200, { "content-type" => type, "cache-control" => cache }, [File.binread(file)]]
      end

      def info
        {
          version: VERSION,
          engine: engine && { name: engine.name, version: engine.version, path: engine.binary },
          rules_path: store.root, read_only: @config.read_only, network: @config.allow_network,
          languages: Languages.all.map { |l| { key: l.key, name: l.name, extension: l.extension, comment: l.comment } },
          severities: Rule::SEVERITIES
        }
      end

      def templates
        { starters: Templates::STARTERS.map { |k, v| { kind: k, title: v[:title] } }, cwe: Templates.all.map(&:summary) }
      end

      def save(slug, b)
        writable!
        yaml = b["yaml"].to_s
        result = Validator.new.validate(yaml)
        if result.rules.empty?
          return json({ error: "could not save: #{result.issues.first&.message}", issues: result.issues.map(&:to_h) }, 422)
        end

        saved = store.write(slug, yaml, test_code: b["test_code"], language: presence(b["language"]))
        json(saved.merge(issues: result.issues.map(&:to_h)))
      end

      def destroy(slug)
        writable!
        store.delete(slug)
        json(deleted: true)
      end

      def validate(b)
        result = Validator.new(engine: (engine if b["engine"])).validate(b["yaml"].to_s)
        rule = result.rules.first
        json(result.to_h.merge(fields: rule && fields_for(rule), rule_count: result.rules.size))
      end

      def run(b)
        raise HttpError.new(503, "no engine found: install opengrep or semgrep and restart") unless engine

        yaml = b["yaml"].to_s
        check = Validator.new.validate(yaml)
        unless check.valid?
          return json(findings: [], errors: check.errors.map { |i| "#{i.path}: #{i.message}" }, annotations: nil)
        end

        json(engine.run(yaml, code: b["code"].to_s, language: presence(b["language"])).to_h)
      end

      def merge(b)
        file = RuleFile.parse(b["yaml"].to_s)
        rule = file.rules.first || raise(ParseError, "no rule found")
        rule.merge_fields(b["fields"] || {})
        json(yaml: file.to_yaml, fields: fields_for(rule))
      end

      def fields_for(rule)
        meta = rule["metadata"].is_a?(Hash) ? rule["metadata"] : {}
        { id: rule.id, message: rule.message, severity: rule.severity, languages: Array(rule.languages),
          mode: rule.mode || "search",
          metadata: { cwe: Array(meta["cwe"]), cve: Array(meta["cve"]), references: Array(meta["references"]),
                      confidence: meta["confidence"], category: meta["category"] } }
      end

      def authorize!(env)
        auth = @config.authorize
        return if auth.nil?

        # Fails closed: anything but a callable or a [user, password] pair denies.
        basic = auth.is_a?(Array) && auth.size == 2
        ok = if auth.respond_to?(:call) then auth.call(env)
             elsif basic then basic_auth?(env, *auth)
             else false
             end
        raise HttpError.new(basic ? 401 : 403, "access denied") unless ok
      end

      def basic_auth?(env, user, pass)
        header = env["HTTP_AUTHORIZATION"].to_s
        return false unless header.start_with?("Basic ")

        given_user, given_pass = header.delete_prefix("Basic ").unpack1("m").split(":", 2)
        OpenSSL.secure_compare(given_user.to_s, user.to_s) & OpenSSL.secure_compare(given_pass.to_s, pass.to_s)
      end

      def writable!
        raise HttpError.new(403, "the editor is in read-only mode") if @config.read_only
      end

      def body(env)
        input = env["rack.input"]
        return {} unless input

        raw = input.read(MAX_BODY + 1).to_s
        input.rewind if input.respond_to?(:rewind)
        raise HttpError.new(413, "request too large") if raw.bytesize > MAX_BODY
        return {} if raw.strip.empty?

        data = JSON.parse(raw)
        raise HttpError.new(400, "expected a JSON object") unless data.is_a?(Hash)

        data
      rescue JSON::ParserError
        raise HttpError.new(400, "invalid JSON")
      end

      def presence(v)
        v.to_s unless v.to_s.strip.empty?
      end

      def json(data, status = 200, headers = {})
        [status, { "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" }.merge(headers),
         [JSON.generate(data)]]
      end
    end
  end
end
