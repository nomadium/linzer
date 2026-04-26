# frozen_string_literal: true

module Linzer
  # Faraday integration for Linzer.
  module Faraday
    # Utility methods for working with Faraday request objects.
    module Utils
      # Create a {::Faraday::Request} from a middleware environment.
      #
      # This builds a minimal request suitable for use with Linzer adapters,
      # preserving the original URL and headers from the environment.
      #
      # @param env [::Faraday::Env] the middleware environment
      # @return [::Faraday::Request] a new request object
      def self.create_request(env)
        ::Faraday::Request.create(env.method) do |req|
          req.params  = ::Faraday::Utils::ParamsHash.new
          req.headers = ::Faraday::Utils::Headers.new(env.request_headers.dup)
          req.options = ::Faraday::ConnectionOptions.from(nil).request
          req.url       env.url
        end
      end
    end
  end
end
