# frozen_string_literal: true

require "time"
require_relative "trapline/version"
require_relative "trapline/configuration"
require_relative "trapline/languages"
require_relative "trapline/rule"
require_relative "trapline/validator"
require_relative "trapline/engine"
require_relative "trapline/store"
require_relative "trapline/cve/record"
require_relative "trapline/cve/client"
require_relative "trapline/templates"
require_relative "trapline/runtime"
require_relative "trapline/generator"
require_relative "trapline/suite"

module Trapline
  class Error < StandardError; end

  class ParseError < Error
    attr_reader :line, :column

    def initialize(message, line: nil, column: nil)
      super(message)
      @line = line
      @column = column
    end
  end

  class NotFound < Error; end
  class InvalidSlug < Error; end
  class NetworkError < Error; end

  class << self
    def config
      @config ||= Configuration.new
    end

    def configure
      yield config
    end

    def reset_config!
      @config = Configuration.new
      @engine = nil
    end

    attr_writer :engine

    def engine
      @engine ||= Engine.detect(config.engine_binary)
    end

    def store
      Store.new(config.rules_path)
    end

    def validate(yaml, engine: false)
      Validator.new(engine: engine ? self.engine : nil).validate(yaml)
    end

    def generate_from_cve(cve_id, **opts)
      Generator.new(**opts).from_cve(cve_id)
    end
  end
end

require_relative "trapline/web/app"
require_relative "trapline/railtie" if defined?(Rails::Railtie)
