#!/usr/bin/env ruby
# frozen_string_literal: true

# Profile: Linzer.verify! with Ed25519 keys
#
# Uses StackProf (sampling CPU profiler) to identify bottlenecks in the
# verification hot path.
#
# Run with:
#   ruby benchmarks/profile_verify_ed25519.rb

require "bundler/setup"
require "linzer"
require "net/http"
require "stackprof"
require "fileutils"

ITERATIONS = Integer(ENV.fetch("ITERATIONS", 5_000))
OUTPUT_DIR = "tmp"
DUMP_FILE  = File.join(OUTPUT_DIR, "stackprof-verify-ed25519.dump")

FileUtils.mkdir_p(OUTPUT_DIR)

key        = Linzer.generate_ed25519_key("bench-ed25519")
uri        = URI("https://example.com/api/resource")
components = %w[@method @path @authority content-type]

# Sign a request once
request = Net::HTTP::Post.new(uri)
request["content-type"] = "application/json"
request.body = '{"hello":"world"}'
Linzer.sign!(request, key: key, components: components)

sig_header   = request["signature"]
input_header = request["signature-input"]

puts "StackProf profile \u2014 Linzer.verify! (Ed25519)"
puts "Ruby #{RUBY_VERSION} / #{RUBY_PLATFORM}"
puts "Iterations: #{ITERATIONS}"
puts

# Warm up
20.times do
  req = Net::HTTP::Post.new(uri)
  req["content-type"]    = "application/json"
  req.body               = '{"hello":"world"}'
  req["signature"]       = sig_header
  req["signature-input"] = input_header
  Linzer.verify!(req, key: key)
end

StackProf.run(
  mode:     :cpu,
  interval: 100,
  out:      DUMP_FILE,
  raw:      true
) do
  ITERATIONS.times do
    req = Net::HTTP::Post.new(uri)
    req["content-type"]    = "application/json"
    req.body               = '{"hello":"world"}'
    req["signature"]       = sig_header
    req["signature-input"] = input_header
    Linzer.verify!(req, key: key)
  end
end

puts "=" * 78
puts "METHOD-LEVEL REPORT (top 30 by self time)"
puts "=" * 78
puts

report = StackProf::Report.new(Marshal.load(File.binread(DUMP_FILE)))
report.print_text(false, 30)

puts
puts "=" * 78
puts "METHOD-LEVEL REPORT (top 30 by total time)"
puts "=" * 78
puts

report.print_text(true, 30)

# Source-annotated hotspots for the top methods
puts
puts "=" * 78
puts "SOURCE ANNOTATIONS FOR TOP METHODS"
puts "=" * 78

top_frames = report.data[:frames]
  .sort_by { |_id, f| -(f[:samples] || 0) }
  .first(10)

top_frames.each do |_frame_id, frame|
  name = frame[:name]
  file = frame[:file]
  next unless file && File.exist?(file)
  puts
  puts "-" * 78
  puts "#{name}  (#{file}:#{frame[:line]})"
  puts "  self: #{frame[:samples]}  total: #{frame[:total_samples]}"
  puts "-" * 78
  report.print_method(name)
end

puts
puts "Dump written to: #{DUMP_FILE}"
