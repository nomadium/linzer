# frozen_string_literal: true

require_relative "lib/linzer/version"

Gem::Specification.new do |spec|
  spec.name = "linzer"
  spec.version = Linzer::VERSION
  spec.authors = ["Miguel Landaeta"]
  spec.email = %w[miguel@miguel.cc]

  spec.summary = "An implementation of HTTP Messages Signatures (RFC9421)"
  spec.homepage = "https://github.com/nomadium/linzer"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = spec.homepage + "/blob/master/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "openssl", "~> 3.0", ">= 3.0.0"
  spec.add_runtime_dependency "starry", "~> 0.2"
  spec.add_runtime_dependency "rack", ">= 2.2", "< 4.0"
  spec.add_runtime_dependency "uri", "~> 1.0", ">= 1.0.2"
  spec.add_runtime_dependency "stringio", "~> 3.1", ">= 3.1.2"
  spec.add_runtime_dependency "logger", "~> 1.7", ">= 1.7.0"
  spec.add_runtime_dependency "forwardable", "~> 1.3", ">= 1.3.3"
  spec.add_runtime_dependency "net-http", ">= 0.6", "< 0.8"
  spec.add_runtime_dependency "cgi", ">= 0.4.2", "< 0.6.0"
end
