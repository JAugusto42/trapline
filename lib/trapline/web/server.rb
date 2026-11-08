# frozen_string_literal: true

require "socket"
require "stringio"
require "uri"

module Trapline
  module Web
    module Server
      module_function

      def start(app, host: "127.0.0.1", port: 9292, logger: $stdout)
        handler = rack_handler
        url = "http://#{host}:#{port}/"
        if handler
          logger.puts "Trapline #{VERSION} at #{url} (#{handler.name})"
          handler.run(app, Host: host, Port: port)
        else
          logger.puts "Trapline #{VERSION} at #{url} (built-in server)"
          Builtin.new(app, host: host, port: port, logger: logger).run
        end
      end

      def rack_handler
        return nil if ENV["TRAPLINE_BUILTIN_SERVER"] == "1"

        require "rackup"
        %w[puma webrick].each do |name|
          return Rackup::Handler.get(name)
        rescue LoadError, NameError
          next
        end
        nil
      rescue LoadError
        nil
      end

      class Builtin
        STATUS = { 200 => "OK", 201 => "Created", 204 => "No Content", 400 => "Bad Request", 401 => "Unauthorized",
                   403 => "Forbidden", 404 => "Not Found", 413 => "Payload Too Large", 422 => "Unprocessable Entity",
                   500 => "Internal Server Error", 502 => "Bad Gateway", 503 => "Service Unavailable" }.freeze

        def initialize(app, host:, port:, logger:)
          @app = app
          @host = host
          @port = port
          @logger = logger
        end

        # Closing the socket from a trap handler while #accept blocks raises
        # ThreadError, so INT/TERM only interrupt the loop.
        def run
          server = TCPServer.new(@host, @port)
          previous = trap("TERM") { Thread.main.raise(Interrupt) }
          loop do
            client = server.accept
            Thread.new(client) { |c| handle(c) }
          end
        rescue Interrupt, IOError
          @logger.puts "Stopping Trapline"
        ensure
          server&.close rescue nil
          trap("TERM", previous || "DEFAULT")
        end

        def handle(client)
          request_line = client.gets("\r\n", 8192).to_s
          method, target, = request_line.split(" ", 3)
          return client.close if method.nil? || target.nil?

          headers = {}
          while (line = client.gets("\r\n", 8192)) && line != "\r\n"
            k, v = line.split(":", 2)
            headers[k.strip.downcase] = v.to_s.strip
          end
          length = headers["content-length"].to_i
          body = length.positive? ? client.read([length, App::MAX_BODY + 1].min).to_s : ""

          uri = URI.parse(target)
          env = {
            "REQUEST_METHOD" => method, "SCRIPT_NAME" => "", "PATH_INFO" => uri.path,
            "QUERY_STRING" => uri.query.to_s, "SERVER_NAME" => @host, "SERVER_PORT" => @port.to_s,
            "SERVER_PROTOCOL" => "HTTP/1.1", "rack.input" => StringIO.new(body), "rack.errors" => $stderr,
            "rack.url_scheme" => "http", "CONTENT_TYPE" => headers["content-type"].to_s,
            "CONTENT_LENGTH" => length.to_s
          }
          headers.each { |k, v| env["HTTP_#{k.upcase.tr('-', '_')}"] = v unless %w[content-type content-length].include?(k) }

          status, res_headers, res_body = @app.call(env)
          payload = String.new(encoding: Encoding::BINARY)
          res_body.each { |chunk| payload << chunk.b }
          res_body.close if res_body.respond_to?(:close)

          client.write "HTTP/1.1 #{status} #{STATUS.fetch(status, 'OK')}\r\n"
          res_headers.each { |k, v| client.write "#{k}: #{v}\r\n" }
          client.write "content-length: #{payload.bytesize}\r\nconnection: close\r\n\r\n"
          client.write payload
          @logger.puts "#{method} #{uri.path} #{status}" if ENV["TRAPLINE_LOG"]
        rescue StandardError => e
          warn "trapline: #{e.class}: #{e.message}"
          client.write "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n" rescue nil
        ensure
          client.close rescue nil
        end
      end
    end
  end
end
