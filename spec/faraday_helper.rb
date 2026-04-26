# frozen_string_literal: true

module Linzer
  module Test
    module FaradayHelper
      extend self

      def new_request(options)
        env = ::Faraday::Env.from(options)
        Linzer::Faraday::Utils.create_request(env)
      end
    end
  end
end
