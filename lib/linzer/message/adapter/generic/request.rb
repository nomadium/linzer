# frozen_string_literal: true

require "cgi"

module Linzer
  class Message
    module Adapter
      # Generic adapters for HTTP messages.
      #
      # These adapters provide a base implementation that can be extended
      # for HTTP libraries not directly supported by Linzer.
      module Generic
        # Generic HTTP request adapter.
        #
        # Provides a base implementation for request message access.
        # Assumes the operation responds to `[]` for header access and
        # has a `uri` attribute.
        #
        # @example Creating a custom adapter
        #   class MyRequestAdapter < Linzer::Message::Adapter::Generic::Request
        #     private
        #     def derived(name)
        #       return @operation.http_method if name.value == "@method"
        #       super
        #     end
        #   end
        class Request < Abstract
          # Creates a new request adapter.
          # @param operation [Object] The HTTP request object
          # @param options [Hash] Additional options (unused in base class)
          def initialize(operation, **options)
            @operation = operation
            freeze
          end

          # Retrieves a header value by name.
          # @param name [String] The header name
          # @return [String, nil] The header value
          def header(name)
            @operation[name]
          end

          # Attaches a signature to the request.
          # @param signature [Signature] The signature to attach
          # @return [Object] The underlying request object
          def attach!(signature)
            signature.to_h.each { |h, v| @operation[h] = v }
            @operation
          end

          private

          def derived(name)
            unimplemented_method = 'Derived field "%s" lookup is not implemented!'

            uri = @operation.uri rescue nil
            raise Error, unimplemented_method % name.value if uri.nil?

            case name.value
            when "@method"         then raise Error, unimplemented_method % name.value
            when "@target-uri"     then uri.to_s
            when "@authority"      then uri.authority.downcase
            when "@scheme"         then uri.scheme.downcase
            when "@request-target" then uri.request_uri
            when "@path"           then uri.path
            when "@query"          then "?%s" % String(uri.query)
            when "@query-param"    then query_param(uri.query, name)
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
            return nil if has_tr # HTTP requests don't have trailer fields
            value = header(name.value.to_s)
            value.dup&.strip
          end
        end
      end
    end
  end
end
