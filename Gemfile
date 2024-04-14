# frozen_string_literal: true

require_relative "lib/linzer/version"

source "https://rubygems.org"

# Specify your gem's dependencies in linzer.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem "standard", "~> 1.3"

# XXX: to-do: drop this when a new starry release happens including the fix for:
# https://github.com/takemar/starry/pull/1
gem "starry", github: "takemar/starry", ref: "4f25b56" if Linzer.ruby_dev?

gem "simplecov", require: false, group: :test
