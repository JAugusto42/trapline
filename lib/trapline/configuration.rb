# frozen_string_literal: true

module Trapline
  class Configuration
    attr_accessor :rules_path, :engine_binary, :engine_timeout, :cve_timeout, :nvd_api_key,
                  :allow_network, :authorize, :read_only

    def initialize
      @rules_path = ENV.fetch("TRAPLINE_RULES_PATH", File.join(Dir.pwd, "rules"))
      @engine_binary = ENV["TRAPLINE_ENGINE"]
      @engine_timeout = Integer(ENV.fetch("TRAPLINE_ENGINE_TIMEOUT", "60"))
      @cve_timeout = Float(ENV.fetch("TRAPLINE_CVE_TIMEOUT", "30"))
      @nvd_api_key = ENV["NVD_API_KEY"]
      @allow_network = ENV["TRAPLINE_OFFLINE"] != "1"
      @authorize = nil
      @read_only = false
    end
  end
end
