# frozen_string_literal: true

require "cgi"

module Linzer
  class Message
    module Adapter
      module NetHTTP
        class Request < Abstract
          def initialize(operation, **options)
            @operation = operation
            freeze
          end

          def headers
            @operation.each_header.to_h
          end

          def attach!(signature)
            signature.to_h.each { |h, v| @operation[h] = v }
            @operation
          end

          private

          def derived(name)
            case name.value
            when :method           then @operation.method
            when :"target-uri"     then @operation.uri.to_s
            when :authority        then @operation.uri.authority.downcase
            when :scheme           then @operation.uri.scheme.downcase
            when :"request-target" then @operation.uri.request_uri
            when :path             then @operation.uri.path
            when :query            then "?%s" % String(@operation.uri.query)
            when :"query-param"    then query_param(name)
            end
          end

          def query_param(name)
            param_name = name.parameters["name"]
            return nil if !param_name
            decoded_param_name = URI.decode_uri_component(param_name)
            params = CGI.parse(@operation.uri.query)
            URI.encode_uri_component(params[decoded_param_name]&.first)
          end

          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr # HTTP requests don't have trailer fields
            value = @operation[name.value.to_s]
            value.dup&.strip
          end
        end
      end
    end
  end
end
