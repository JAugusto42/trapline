# frozen_string_literal: true

Trapline.configure do |config|
  # Where rules and their test files live (`semgrep --test` layout).
  config.rules_path = Rails.root.join("security", "semgrep").to_s

  # Engine binary. nil = look for `opengrep`, then `semgrep`, on PATH.
  # config.engine_binary = "/usr/local/bin/opengrep"

  # Who can open the editor. Receives the Rack env; return true to allow access.
  # Example with Devise/Warden:
  #   config.authorize = ->(env) { env["warden"]&.user&.admin? }
  # Or HTTP Basic:
  #   config.authorize = [ENV.fetch("TRAPLINE_USER"), ENV.fetch("TRAPLINE_PASSWORD")]
  config.authorize = ->(_env) { Rails.env.development? }

  # Read-only outside development (the editor still validates and runs rules).
  config.read_only = !Rails.env.development?

  # NVD/OSV lookups by the CVE generator.
  # config.allow_network = true
  # config.nvd_api_key = ENV["NVD_API_KEY"]
end
