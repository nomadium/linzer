#!/usr/bin/env ruby
# frozen_string_literal: true

# Benchmark: Linzer.sign! with Ed25519 keys
#
# Establishes a baseline for signature creation performance.
# Run with: ruby benchmarks/sign_ed25519.rb

require "bundler/setup"
require "linzer"
require "net/http"
require "benchmark/ips"

# Generate an Ed25519 key pair once (not part of the benchmark)
key = Linzer.generate_ed25519_key("bench-ed25519")

# Build a representative HTTP request to sign
uri = URI("https://example.com/api/resource")
components = %w[@method @path @authority content-type]

puts "Linzer.sign! benchmark — Ed25519"
puts "Ruby #{RUBY_VERSION} / #{RUBY_PLATFORM}"
puts "OpenSSL #{OpenSSL::VERSION}"
puts

Benchmark.ips do |x|
  x.config(time: 10, warmup: 3)

  x.report("Linzer.sign! (ed25519)") do
    request = Net::HTTP::Post.new(uri)
    request["content-type"] = "application/json"
    request.body = '{"hello":"world"}'

    Linzer.sign!(request,
      key: key,
      components: components
    )
  end

  x.compare!
end
