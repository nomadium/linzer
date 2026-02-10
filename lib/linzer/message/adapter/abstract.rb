# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      # Abstract base class for HTTP message adapters.
      #
      # Adapters provide a unified interface for accessing HTTP message
      # components regardless of the underlying HTTP library. Each adapter
      # implements field retrieval, header access, and signature attachment
      # for a specific HTTP message type.
      #
      # @abstract Subclass and implement {#header}, {#attach!}, {#derived},
      #   and {#field} to create a new adapter.
      #
      # @see Rack::Request Rack request adapter
      # @see Rack::Response Rack response adapter
      # @see NetHTTP::Request Net::HTTP request adapter
      # @see NetHTTP::Response Net::HTTP response adapter
      class Abstract
        # @raise [Error] This class cannot be instantiated directly
        def initialize(operation, **options)
          raise Linzer::Error, "Cannot instantiate an abstract class!"
        end

        # Checks if this adapter wraps an HTTP request.
        # @return [Boolean] true if the wrapped message is a request
        def request?
          self.class.to_s.include?("Request")
        end

        # Checks if this adapter wraps an HTTP response.
        # @return [Boolean] true if the wrapped message is a response
        def response?
          self.class.to_s.include?("Response")
        end

        # Checks if this response has an attached request.
        #
        # Attached requests enable the `;req` parameter for accessing
        # request fields from a response signature.
        #
        # @return [Boolean] true if an attached request is present
        def attached_request?
          response? && !!@attached_request
        end

        # Checks if a component exists in the message.
        #
        # @param f [String] The component identifier
        # @return [Boolean] true if the component can be retrieved
        def field?(f)
          !!self[f]
        end

        # Retrieves a component value from the message.
        #
        # Handles both regular header fields and derived components,
        # including parameter processing (`;sf`, `;bs`, `;req`, `;key`).
        #
        # @param field [String, FieldId] The component identifier
        # @return [String, Integer, nil] The component value, or nil if not found
        #
        # @example Header field
        #   adapter["content-type"]  # => "application/json"
        #
        # @example Derived component
        #   adapter["@method"]  # => "POST"
        #
        # @example With structured field parameter
        #   adapter['"example-dict";key="a"']  # => "1"
        def [](field)
          field_id = field.is_a?(FieldId) ? field : parse_field_name(field)
          return nil if field_id.nil? || field_id.item.nil?
          retrieve(field_id.item, field_id.derived? ? :derived : :field)
        end

        # Retrieves a raw header value by name.
        #
        # @abstract Subclasses must implement this method.
        # @param name [String] The header name
        # @return [String, nil] The header value
        def header(name)
          raise Linzer::Error, "Sub-classes are required to implement this method!"
        end

        # Attaches a signature to the underlying HTTP message.
        #
        # @abstract Subclasses must implement this method.
        # @param signature [Signature] The signature to attach
        # @return [Object] The underlying HTTP message
        def attach!(signature)
          raise Linzer::Error, "Sub-classes are required to implement this method!"
        end

        private

        # Parses a field name string into a FieldId.
        # @return [FieldId, nil] The parsed identifier, or nil if invalid
        def parse_field_name(field_name)
          field_id  = FieldId.new(field_name: field_name)
          component = field_id.item

          return nil if component.nil?

          # RFC 9421 Section 2.2.9: @status is only valid for responses
          invalid = "@status component identifier is invalid in a request message"
          raise Error, invalid if request? && component.value == "@status"

          field_id
        end

        # Validates that an attached message is a request.
        # @raise [Error] If the message is not a request
        def validate_attached_request(message)
          msg = "The attached message is not a valid HTTP request!"
          raise Linzer::Error, msg unless message.request?
        end

        # Validates component identifier parameters.
        # @return [Object, nil] The validated name, or nil if invalid
        def validate_parameters(name, method)
          has_unknown = name.parameters.any? { |p, _| !KNOWN_PARAMETERS.include?(p) }
          return nil if has_unknown

          has_name = name.parameters["name"]
          has_req  = name.parameters["req"]
          has_sf   = name.parameters["sf"] || name.parameters.key?("key")
          has_bs   = name.parameters["bs"]
          value    = name.value

          # Section 2.2.8 of RFC 9421: name param only for @query-param
          return nil if has_name && value != "@query-param"

          # No derived values come from trailers section
          return nil if method == :derived && name.parameters["tr"]

          # RFC 9421 Section 2.1: bs incompatible with sf/key
          return nil if has_sf && has_bs

          # req param only makes sense on responses
          return nil if has_req && !response?

          name
        end

        # Known component identifier parameters from RFC 9421.
        KNOWN_PARAMETERS = %w[sf key bs req tr name]
        private_constant :KNOWN_PARAMETERS

        # Retrieves a component value with parameter processing.
        def retrieve(name, method)
          if !name.parameters.empty?
            valid_params = validate_parameters(name, method)
            return nil if !valid_params
          end

          has_req = name.parameters["req"]
          has_sf  = name.parameters["sf"] || name.parameters.key?("key")
          has_bs  = name.parameters["bs"]

          if has_req
            name.parameters.delete("req")
            return req(name, method)
          end

          value = send(method, name)

          case
          when has_sf
            key = name.parameters["key"]
            sf(value, key)
          when has_bs then bs(value)
          else value
          end
        end

        # Processes a structured field value with optional key extraction.
        # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1
        def sf(value, key = nil)
          dict = Starry.parse_dictionary(value)

          if key
            obj = dict[key]
            Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj)
          else
            Starry.serialize(dict)
          end
        end

        # Binary-wraps a field value.
        # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3
        def bs(value)
          Starry.serialize(value.encode(Encoding::ASCII_8BIT))
        end

        # Retrieves a trailer field value.
        # @abstract Subclasses should implement if trailer support is needed.
        def tr(trailer)
          raise Error, "Sub-classes are required to implement this method!"
        end

        # Retrieves a field from the attached request.
        def req(field, method)
          attached_request? ? @attached_request[String(field)] : nil
        end
      end
    end
  end
end
