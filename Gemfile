# frozen_string_literal: true

require_relative "lib/linzer/version"

source "https://rubygems.org"

# Specify your gem's dependencies in linzer.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem "standard", "~> 1.3"

# XXX: to-do: drop this when starry bug in ruby-dev is fixed (LoadError)
# https://github.com/takemar/starry/pull/1
if Linzer.ruby_dev?
  gem "starry", github: "nomadium/starry",
                branch: "add-base64-gem-to-dependencies"
end
