# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Faraday
        # Adapter for {Faraday::Request} objects from faraday gem.
        #
        # Extends the generic request adapter with faraday-specific
        # status code retrieval.
        #
        # @note Not loaded automatically to avoid making faraday gem a dependency.
        #
        # @see https://github.com/lostisland/faraday faraday gem
        class Request < Generic::Request
          private

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

          def query_param(uri_query, name)
            param_name = name.parameters["name"]
            return nil if !param_name
            decoded_param_name = URI.decode_uri_component(param_name)
            params = CGI.parse(uri_query)
            URI.encode_uri_component(params[decoded_param_name]&.first)
          end

          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr
            value = @operation.headers[name.value.to_s]
            value.dup&.strip
          end

          def uri
            uri = @operation.path.dup
            uri.query = URI.encode_www_form(@operation.params)
            uri
          end

          def uri_query
            url = @operation.path
            # Prefer the raw query string from the URI when available,
            # as Faraday normalises percent-encoding when parsing params
            # (e.g. %2D → -), which breaks signature verification.
            url.query || uri.query
          end
        end
      end
    end
  end
end
