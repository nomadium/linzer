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
    alias_method :components, :metadata
    alias_method :bytes, :value

    def to_h
      {
        "signature" => Starry.serialize({label => value}),
        "signature-input" =>
          Starry.serialize({label =>
            Starry::InnerList.new(components, parameters)})
      }
    end

    class << self
      private :new

      def build(headers, options = {})
        validate headers

        input = parse_field(headers, "signature-input")
        reject_multiple_signatures if input.size > 1 && options[:label].nil?
        label = options[:label] || input.keys.first

        signature = parse_field(headers, "signature")
        fail_with_signature_not_found label unless signature.key?(label)

        raw_signature = signature[label].value

        fail_due_invalid_components unless input[label].value.respond_to?(:each)

        components = input[label].value.map(&:value)
        parameters = input[label].parameters

        new(components, raw_signature, label, parameters)
      end

      private

      def validate(headers)
        raise Error.new "Cannot build signature: Request headers cannot be null"      if headers.nil?
        raise Error.new "Cannot build signature: No request headers found"            if headers.empty?
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

      def parse_field(hsh, field_name)
        Message.parse_structured_dictionary(hsh[field_name], field_name)
      end
    end
  end
end
