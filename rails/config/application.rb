require_relative "boot"

# Minimal Rails: we only need the router + Action Controller (API mode).
require "rails"
require "action_controller/railtie"

Bundler.require(*Rails.groups)

module SsrfLab
  class Application < Rails::Application
    config.load_defaults 7.1

    # API-only: no views, cookies or sessions needed for this lab.
    config.api_only = true

    # Keep the app self-contained so `bundle exec rspec` boots with no extras.
    config.eager_load = false
    config.secret_key_base = "ssrf-lab-not-a-secret"
    config.logger = Logger.new($stdout)
    config.log_level = :warn
  end
end
