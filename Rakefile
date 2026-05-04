# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "standard/rake"

desc "Run RSpec integration examples"
task :integration do
  sh "bundle exec rspec -t integration spec/integration/**"
end

desc "Run benchmarks"
task :benchmarks do
  sh "bundle exec ruby benchmarks/sign.rb"
  sh "bundle exec ruby benchmarks/verify.rb"
end

task default: %i[spec standard]
task all: %i[integration default]
