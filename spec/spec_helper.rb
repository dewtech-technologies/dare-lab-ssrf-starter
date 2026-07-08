# frozen_string_literal: true

require "webmock/rspec"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "safe_fetch"

# Disable ALL real network connections. Every request must be stubbed.
WebMock.disable_net_connect!(allow_localhost: false)

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random

  config.after do
    WebMock.reset!
  end
end
