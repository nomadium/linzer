# frozen_string_literal: true

module Linzer
  class Signature
    def initialize(metadata, value, label, parameters = {})
      @metadata   = metadata.clone.freeze
      @value      = value.clone.freeze
      @parameters = parameters.clone.freeze
      @label      = label.clone.freeze
      freeze
    end

    attr_reader  :metadata, :value, :parameters, :label
    alias_method :serialized_components, :metadata
    alias_method :bytes, :value

    def components
      FieldId.deserialize_components(serialized_components)
    end

    def created
      Integer(parameters["created"])
    rescue
      return nil if parameters["created"].nil?
      raise Error.new "Signature has a non-integer `created` parameter"
    end

    def older_than?(seconds)
      raise Error.new "Signature is missing the `created` parameter" if created.nil?
      (Time.now.to_i - created) > seconds
    end

    def to_h
      {
        "signature"       => Starry.serialize({label => value}),
        "signature-input" => Starry.serialize({
          label => Starry::InnerList.new(
            serialized_components.map { |c| Starry.parse_item(c) },
            parameters
          )
        })
      }
    end

    class << self
      private :new

      def build(headers, options = {})
        basic_validate headers
        headers.transform_keys!(&:downcase)
        validate headers

        input = parse_structured_field(headers, "signature-input")
        reject_multiple_signatures if input.size > 1 && options[:label].nil?
        label = options[:label] || input.keys.first

        signature = parse_structured_field(headers, "signature")
        fail_with_signature_not_found label unless signature.key?(label)

        raw_signature =
          signature[label].value
            .force_encoding(Encoding::ASCII_8BIT)

        fail_due_invalid_components unless input[label].value.respond_to?(:each)

        components = input[label].value.map { |c| Starry.serialize_item(c) }
        parameters = input[label].parameters

        new(components, raw_signature, label, parameters)
      end

      private

      def basic_validate(headers)
        raise Error.new "Cannot build signature: Request headers cannot be null"      if headers.nil?
        raise Error.new "Cannot build signature: No request headers found"            if headers.empty?
      end

      def validate(headers)
        raise Error.new "Cannot build signature: No \"signature-input\" header found" unless headers.key?("signature-input")
        raise Error.new "Cannot build signature: No \"signature\" header found"       unless headers.key?("signature")
      end

      def reject_multiple_signatures
        raise Error.new "Multiple signatures found but none was selected."
      end

      def fail_with_signature_not_found(label)
        raise Error.new "Signature label not found: \"#{label}\""
      end

      def fail_due_invalid_components
        raise Error.new "Unexpected value for covered components."
      end

      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end

      def parse_structured_field(hsh, field_name)
        # Serialized Structured Field values for HTTP are ASCII strings.
        # See: RFC 8941 (https://datatracker.ietf.org/doc/html/rfc8941)
        value = hsh[field_name].encode(Encoding::US_ASCII)
        parse_structured_dictionary(value, field_name)
      end
    end
  end
end
