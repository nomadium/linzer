# frozen_string_literal: true

module Linzer
  # Faraday integration for Linzer.
  #
  # @see file:lib/linzer/faraday.rb
  module Faraday
    # Utility methods for converting Faraday middleware objects into
    # types compatible with Linzer adapters.
    module Utils
      # Creates a {::Faraday::Request} from a middleware environment.
      #
      # Builds a minimal request suitable for use with
      # {Linzer::Message::Adapter::Faraday::Request}, preserving the
      # original HTTP method, URL, and headers from the environment.
      #
      # Preserves the environment's request options when present, so that
      # a +params_encoder+ configured on the connection or request is
      # carried over. The adapter re-encodes query parameters when
      # deriving +@target-uri+ and friends, and must use the same encoder
      # Faraday used to write the URL, or the signed value will not match
      # the URI actually sent.
      #
      # @param env [::Faraday::Env] the middleware environment
      # @return [::Faraday::Request] a new request object
      def self.create_request(env)
        ::Faraday::Request.create(env.method) do |req|
          req.params  = ::Faraday::Utils::ParamsHash.new
          req.headers = ::Faraday::Utils::Headers.new(env.request_headers.dup)
          req.options = env.request || ::Faraday::ConnectionOptions.from(nil).request
          req.url       env.url
        end
      end
    end
  end
end
