# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Faraday
        # Adapter for {::Faraday::Request} objects from the faraday gem.
        #
        # Extends the generic request adapter with faraday-specific
        # derived component retrieval, field lookup, and URI handling.
        #
        # @note Not loaded automatically to avoid making faraday a hard
        #   dependency. Require +"linzer/faraday"+ to register this adapter.
        #
        # @see Generic::Request
        # @see https://github.com/lostisland/faraday faraday gem
        class Request < Generic::Request
          private

          # Resolves a derived component value from the request.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [String, nil] the derived value, or +nil+ if unknown
          def derived(name)
            url = @operation.path
            case name.value
            when "@method"         then @operation.http_method.to_s.upcase
            when "@target-uri"     then uri.to_s
            when "@authority"      then url.authority.downcase
            when "@scheme"         then url.scheme.downcase
            when "@request-target" then uri.request_uri
            when "@path"           then url.path
            when "@query"          then "?%s" % String(uri_query)
            when "@query-param"    then query_param(uri_query, name)
            end
          end

          # Builds the full URI including query parameters.
          #
          # Encodes the query with the request's own +params_encoder+,
          # mirroring how faraday builds the URL it puts on the wire
          # (+Faraday::Connection#build_env+). Encoding it independently
          # here would diverge from the URI actually sent: notably
          # +URI.encode_www_form+ always encodes a space as +++, while
          # faraday honours the process-wide
          # +Faraday::Utils.default_space_encoding+, which other gems may
          # set to +%20+. The signer would then cover a +@target-uri+ the
          # verifier cannot reproduce from the request it received.
          #
          # An empty query is left as +nil+ rather than +""+, as assigning
          # +""+ would append a stray +?+ that faraday does not send.
          #
          # @return [URI] the complete request URI with encoded query string
          def uri
            uri = @operation.path.dup
            query = @operation.params.to_query(@operation.options.params_encoder)
            uri.query = query unless query.empty?
            uri
          end

          # Returns the raw query string from the request URI.
          #
          # Prefers the raw query string from the URI when available,
          # as Faraday normalises percent-encoding when parsing params
          # (e.g. +%2D+ becomes +-+), which would break signature
          # verification.
          #
          # @return [String, nil] the raw query string
          def uri_query
            url = @operation.path
            url.query || uri.query
          end
        end
      end
    end
  end
end
