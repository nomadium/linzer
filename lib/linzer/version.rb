# frozen_string_literal: true

module Linzer
  VERSION = "0.5.2"

  def self.ruby_dev?
    RUBY_ENGINE == "ruby" && RUBY_PATCHLEVEL == -1 && /\Aruby 3.[0-9].0dev/ =~ RUBY_DESCRIPTION
  end
end
