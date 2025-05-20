# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      class Abstract
        def initialize(operation, **options)
          raise Linzer::Error, "Cannot instantiate an abstract class!"
        end

        def request?
          self.class.to_s.include?("Request")
        end

        def response?
          self.class.to_s.include?("Response")
        end

        # XXX: attached request as specified in RFC has to be tested for Net::HTTP classes
        # and custom HTTP message classes
        def attached_request?
          response? && !!@attached_request
        end

        def field?(f)
          !!self[f]
        end

        def [](field_name)
          name = parse_field_name(field_name)
          return nil if name.nil?

          if field_name.start_with?("@")
            retrieve(name, :derived)
          else
            retrieve(name, :field)
          end
        end

        def header(name)
          raise Linzer::Error, "Sub-classes are required to implement this method!"
        end

        def attach!(signature)
          raise Linzer::Error, "Sub-classes are required to implement this method!"
        end

        private

        def parse_field_name(field_name)
          if field_name&.start_with?("@")
            Starry.parse_item(field_name[1..])
          else
            Starry.parse_item(field_name)
          end
        rescue => _
          nil
        end

        def validate_attached_request(message)
          msg = "The attached message is not a valid HTTP request!"
          raise Linzer::Error, msg unless message.request?
        end

        def validate_parameters(name, method)
          has_unknown = name.parameters.any? { |p, _| !KNOWN_PARAMETERS.include?(p) }
          return nil if has_unknown

          has_name = name.parameters["name"]
          has_req  = name.parameters["req"]
          has_sf   = name.parameters["sf"] || name.parameters.key?("key")
          has_bs   = name.parameters["bs"]
          value    = name.value

          # Section 2.2.8 of RFC 9421
          return nil if has_name && value != :"query-param"

          # No derived values come from trailers section
          return nil if method == :derived && name.parameters["tr"]

          # From: 2.1. HTTP Fields:
          # The bs parameter, which requires the raw bytes of the field values
          # from the message, is not compatible with the use of the sf or key
          # parameters, which require the parsed data structures of the field
          # values after combination
          return nil if has_sf && has_bs

          # req param only makes sense on responses with an associated request
          # return nil if has_req && (!response? || !attached_request?)
          return nil if has_req && !response?

          name
        end

        KNOWN_PARAMETERS = %w[sf key bs req tr name]
        private_constant :KNOWN_PARAMETERS

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

        def sf(value, key = nil)
          dict = Starry.parse_dictionary(value)

          if key
            obj = dict[key]
            Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj)
          else
            Starry.serialize(dict)
          end
        end

        def bs(value)
          Starry.serialize(value.encode(Encoding::ASCII_8BIT))
        end

        def tr(trailer)
          @operation.body.trailers[trailer.value.to_s]
        end

        def req(field, method)
          case method
          when :derived then @attached_request["@#{field}"]
          when :field   then @attached_request[field.to_s]
          end
        end
      end
    end
  end
end
