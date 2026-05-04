# frozen_string_literal: true

require_relative "lib/linzer/version"

source "https://rubygems.org"

# Specify your gem's dependencies in linzer.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem "securerandom", ">= 0.3.2"

gem "standard", "~> 1.3"

group :test do
  gem "http", ">= 5.0", "< 7.0", require: false
  gem "simplecov", require: false
  gem "sinatra",   require: false
  gem "webrick",   require: false
  gem "rackup",    require: false
  gem "jwt-eddsa", require: false
  gem "faraday",  ">= 2.0", require: false
  gem "stringio", "~> 3.1", ">= 3.1.2", require: false
end

group :development do
  gem "irb"
  gem "rdoc"
  gem "yard", "~> 0.9"
  gem "benchmark_driver", require: false
  gem "benchmark",        require: false
end
