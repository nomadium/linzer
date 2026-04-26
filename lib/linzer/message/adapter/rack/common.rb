# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      # Rack HTTP message adapters.
      #
      # Provides adapters for {::Rack::Request} and {::Rack::Response} objects.
      module Rack
        # Shared functionality for Rack request and response adapters.
        # @api private
        module Common
          DERIVED_COMPONENT = {
            "@method"         => :request_method,
            "@authority"      => :authority,
            "@path"           => :path_info,
            "@status"         => :status,
            "@target-uri"     => :url,
            "@scheme"         => :scheme,
            "@request-target" => :fullpath,
            "@query"          => :query_string
          }.freeze
          private_constant :DERIVED_COMPONENT

          private

          # Validates that the operation is exclusively a request or response.
          # @raise [Error] if the operation is both or neither
          def validate
            msg = "Message instance must be an HTTP request or response"
            raise Error.new msg if response? == request?
          end

          # Validates that a header name is non-empty.
          #
          # @param name [String] the header name
          # @return [String] the validated header name
          # @raise [ArgumentError] if the name is blank
          # @raise [Linzer::Error] if the name is otherwise invalid
          def validate_header_name(name)
            raise ArgumentError.new, "Blank header name." if name.empty?
            name.to_str
          rescue => ex
            # :nocov:
            # XXX: this block of code seems to be unreachable
            err_msg = "Invalid header name: '#{name}'"
            raise Linzer::Error, err_msg, cause: ex
            # :nocov:
          end

          # Converts an HTTP header name to Rack's environment key format.
          #
          # Rack stores headers as uppercase with underscores and an +HTTP_+
          # prefix, except for +Content-Type+ and +Content-Length+.
          #
          # @param field_name [String] the HTTP header name (e.g. +"content-type"+)
          # @return [String] the Rack env key (e.g. +"CONTENT_TYPE"+ or +"HTTP_ACCEPT"+)
          def rack_header_name(field_name)
            validate_header_name field_name

            rack_name = field_name.upcase.tr("-", "_")
            case field_name.downcase
            when "content-type", "content-length"
              rack_name
            else
              "HTTP_#{rack_name}"
            end
          end

          # Resolves a derived component value from the Rack request/response.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [String, nil] the derived value, or +nil+ if unknown
          def derived(name)
            method = DERIVED_COMPONENT[name.value]

            value = case name.value
            when "@query"       then derive(@operation, method)
            when "@query-param" then query_param(name)
            end

            return nil if !method && !value
            value || derive(@operation, method)
          end

          # Retrieves an HTTP field value from the Rack request or response.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [String, nil] the stripped header value, or +nil+ if the
          #   field has a +tr+ (trailer) parameter or is not present
          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr

            item_value  = String(name.value)
            field_value = if request?
              rack_header_name = rack_header_name(item_value)
              @operation.env[rack_header_name]
            else
              @operation.get_header(item_value)
            end

            field_value.dup&.strip
          end

          # Invokes a method on the Rack operation to extract a derived value.
          #
          # Applies post-processing for +@query+ (prepends +?+) and
          # +@authority+/+@scheme+ (downcases).
          #
          # @param operation [Rack::Request, Rack::Response] the Rack object
          # @param method [Symbol] the method to call
          # @return [String, nil] the derived value
          def derive(operation, method)
            return nil unless operation.respond_to?(method)
            value = operation.public_send(method)
            return "?" + value    if method == :query_string
            return value.downcase if %i[authority scheme].include?(method)
            value
          end

          # Extracts a single query parameter value by name.
          #
          # @param name [Starry::Item] the component with a +name+ parameter
          # @return [String, nil] the percent-encoded parameter value, or
          #   +nil+ if the parameter is missing or not found
          def query_param(name)
            param_name = name.parameters["name"]
            return nil if !param_name
            decoded_param_name = URI.decode_uri_component(param_name)
            URI.encode_uri_component(@operation.params.fetch(decoded_param_name))
          rescue => _
            nil
          end
        end
      end
    end
  end
end
