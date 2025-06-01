# frozen_string_literal: true

require_relative "lib/linzer/version"

source "https://rubygems.org"

# Specify your gem's dependencies in linzer.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem "securerandom", "~> 0.3.2" # securerandom-0.4.0 requires ruby >= 3.1.0

gem "standard", "~> 1.3"

group :test do
  gem "simplecov", require: false
  gem "http",      require: false
  gem "sinatra",   require: false
  gem "webrick",   require: false
  gem "rackup",    require: false
  gem "jwt-eddsa", require: false
end
