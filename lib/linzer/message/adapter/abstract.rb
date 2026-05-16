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
      # @abstract Subclass and implement {#header}, {#derived}, and {#field}
      #   to create a new adapter.
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
          field_id = (field.is_a?(FieldId) || field.is_a?(Field::FastIdentifier)) ? field : parse_field_name(field)
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

        # Checks whether the request contains HTTP Message Signature headers.
        #
        # Returns true if either the "signature-input" or "signature" header
        # is present.
        #
        # @return [Boolean] true if the request includes HTTP Message Signature headers
        def has_signature?
          !!header("signature-input") || !!header("signature")
        end

        # Attaches a signature to the underlying HTTP message.
        #
        # @param signature [Signature] The signature to attach
        # @return [Object] The underlying HTTP message
        def attach!(signature, additional_headers: {})
          signature_headers = signature.to_h

          unless has_signature?
            signature_headers.each { |h, v| set_header!(h, v) }
            if !additional_headers.empty?
              additional_headers.each { |h, v| set_header!(h, v) }
            end
            return @operation
          end

          signature_headers.each do |hdr, value|
            merged = Starry.parse_dictionary(String(header(hdr)))
            merged.merge!(Starry.parse_dictionary(value))
            set_header!(hdr, Starry.serialize_dictionary(merged))
          end

          if !additional_headers.empty?
            additional_headers.each { |h, v| set_header!(h, v) }
          end
          @operation
        rescue Starry::ParseError => e
          raise Error,
                "Cannot attach signature, invalid signature header(s)!",
                cause: e
        end

        private

        # Parses a field name string into a FieldId.
        #
        # @param field_name [String] the component identifier string
        # @return [FieldId, nil] the parsed identifier, or +nil+ if invalid
        # @raise [Error] if +@status+ is used in a request message
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

        # Validates component identifier parameters against RFC 9421 rules.
        #
        # @param name [Starry::Item] the parsed component identifier
        # @param method [Symbol] +:derived+ or +:field+
        # @return [Starry::Item, nil] the validated name, or +nil+ if
        #   the parameter combination is invalid
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
        #
        # Handles +;req+, +;sf+, +;key+, and +;bs+ parameters by
        # delegating to the corresponding helper methods.
        #
        # @param name [Starry::Item] the parsed component identifier
        # @param method [Symbol] +:derived+ or +:field+
        # @return [String, Integer, nil] the component value
        def retrieve(name, method)
          # Fast path: no parameters means no special handling needed
          return send(method, name) if name.parameters.empty?

          valid_params = validate_parameters(name, method)
          return nil if !valid_params

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
        #
        # @param value [String] the raw header value to parse as a dictionary
        # @param key [String, nil] if present, extracts a single dictionary member
        # @return [String] the serialized structured field value
        # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1
        def sf(value, key = nil)
          dict = Starry.parse_dictionary(value)

          if key
            obj = dict[key]
            Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj)
          else
            Starry.serialize(dict)
          end
        rescue # XXX: Is this a bug in Starry. If value == nil, then Starry crashes
          # instead of just raising Starry::ParseError
          nil
        end

        # Binary-wraps a field value as a byte sequence.
        #
        # @param value [String] the header value to wrap
        # @return [String] the serialized byte sequence
        # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3
        def bs(value)
          Starry.serialize(value.encode(Encoding::ASCII_8BIT))
        end

        # Retrieves a trailer field value.
        #
        # @abstract Subclasses should implement if trailer support is needed.
        # @param trailer [Object] the trailer field identifier
        # @return [String, nil] the trailer value
        # @raise [Error] always, since no built-in adapters support trailers
        def tr(trailer)
          raise Error, "Sub-classes are required to implement this method!"
        end

        # Retrieves a field from the attached request (for +;req+ parameter).
        #
        # @param field [Starry::Item] the component identifier
        # @param method [Symbol] +:derived+ or +:field+
        # @return [String, nil] the value from the attached request, or
        #   +nil+ if no request is attached
        def req(field, method)
          attached_request? ? @attached_request[String(field)] : nil
        end
      end
    end
  end
end
