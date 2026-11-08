# frozen_string_literal: true

require "rails/generators"

module Trapline
  module Generators
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)
      desc "Installs Trapline: initializer, editor route and rules folder"

      class_option :path, type: :string, default: "/trapline", desc: "Path where the editor will be mounted"

      def create_initializer
        template "initializer.rb", "config/initializers/trapline.rb"
      end

      def mount_editor
        route <<~RUBY.strip
          # semgrep/opengrep rule editor. See config/initializers/trapline.rb
          mount Trapline::Web::App.new, at: "#{options[:path]}"
        RUBY
      end

      def create_rules_dir
        create_file "security/semgrep/.keep", ""
      end

      def done
        say "\nTrapline installed. Run `bin/rails server` and open #{options[:path]}", :green
        say "Also install the engine: `pip install semgrep` or the opengrep binary."
      end
    end
  end
end
