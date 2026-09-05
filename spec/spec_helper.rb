# frozen_string_literal: true

require "simplecov"

SimpleCov.start do
  enable_coverage :branch

  excluded_paths = [
    # Excluded because they are not relevant for unit/integration tests
    # coverage statistics.
    "/spec/integration/support",
    "/spec/rack_helper.rb",

    # These files are excluded because it is not possible to reach
    # 100% coverage, a few tests are excluded in older Ruby versions.
    "/spec/linzer_spec.rb",
    "/spec/rack_auth_signature_spec.rb",
    "/spec/rsa_pss_spec.rb",
    "/spec/rsa_spec.rb",
    "/spec/verifier_spec.rb"
  ]

  filter_method = respond_to?(:skip) ? :skip : :add_filter
  excluded_paths.each { |path| public_send(filter_method, path) }
end

require "securerandom"

require "linzer"
require_relative "rfc9421_examples"
require_relative "rack_helper"
require_relative "request_helper"
require_relative "faraday_helper"

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
