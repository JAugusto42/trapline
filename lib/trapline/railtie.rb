# frozen_string_literal: true

module Trapline
  class Railtie < ::Rails::Railtie
    config.trapline = ActiveSupport::OrderedOptions.new

    initializer "trapline.defaults", before: :load_config_initializers do |app|
      Trapline.config.rules_path = app.root.join("security", "semgrep").to_s unless ENV["TRAPLINE_RULES_PATH"]
      Trapline.config.read_only = !Rails.env.development?
    end

    initializer "trapline.config", after: :load_config_initializers do |app|
      app.config.trapline.each do |key, value|
        Trapline.config.public_send("#{key}=", value) if Trapline.config.respond_to?("#{key}=")
      end
    end

    rake_tasks do
      load File.expand_path("../tasks/trapline.rake", __dir__)
    end

    generators do
      require_relative "../generators/trapline/install_generator"
    end
  end
end
