ENV["RAILS_ENV"] ||= "test"

require_relative "../config/environment"

require "rspec/rails"
require "webmock/rspec"

# No real network in this lab: WebMock blocks everything not explicitly stubbed.
WebMock.disable_net_connect!(allow_localhost: false)

RSpec.configure do |config|
  config.infer_spec_type_from_file_location!
  config.use_transactional_fixtures = false
end
