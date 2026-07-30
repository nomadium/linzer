# frozen_string_literal: true

module Linzer
  module Test
    module FaradayHelper
      extend self

      def new_request(options)
        env = ::Faraday::Env.from(options)
        Linzer::Faraday::Utils.create_request(env)
      end

      # Temporarily sets faraday's process-wide space encoding, restoring
      # the previous value afterwards so it does not leak between examples.
      def with_space_encoding(encoding)
        previous = ::Faraday::Utils.default_space_encoding
        ::Faraday::Utils.default_space_encoding = encoding
        yield
      ensure
        ::Faraday::Utils.default_space_encoding = previous
      end
    end
  end
end
