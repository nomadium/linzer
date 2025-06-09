# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  enable_coverage :branch
  add_filter "/spec/integration/support"
  add_filter "/spec/rack_helper.rb"
end

require "securerandom"

require "linzer"
require_relative "rfc9421_examples"
require_relative "rack_helper"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Do not run integration tests by default
  config.filter_run_excluding :integration

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
