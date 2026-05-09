# frozen_string_literal: true

# class << self
#   delegate :serialize,
#            :serialize_dictionary,
#            :parse_item,
#            to: Starry
# end

module Linzer
  module HTTP
    # Utilities for serializing HTTP Structured Fields as defined in RFC 8941.
    #
    # This module currently provides helpers for serializing HTTP Message
    # Signature parameters as used by RFC 9421.
    #
    # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
    # @see https://www.rfc-editor.org/rfc/rfc9421 RFC 9421
    module StructuredField
      InnerList  = Starry::InnerList
      Item       = Starry::Item

      # XXX: Add rubydoc
      def self.parse_dictionary(str, field_name: nil)
        # Serialized Structured Field values for HTTP are ASCII strings.
        # See: RFC 8941 (https://datatracker.ietf.org/doc/html/rfc8941)
        Starry.parse_dictionary(str.encode(Encoding::US_ASCII))
      rescue Starry::ParseError => ex
        raise Error,
              "Cannot parse \"#{field_name}\" field!",
              cause: ex
      end

      # Serializes signature parameters to the RFC 8941 string format.
      #
      # Integers are bare, strings are double-quoted. This covers all
      # parameter types used in RFC 9421 signatures (created, expires,
      # keyid, nonce, alg, tag).
      #
      # @example Serialize signature parameters
      #   StructuredField.serialize_parameters(
      #     created: 1700000000,
      #     keyid: "my-key"
      #   )
      #   # => ';created=1700000000;keyid="my-key"'
      #
      # @param parameters [Hash{Symbol,String => Object}]
      #   The parameters to serialize.
      #
      # @return [String]
      #   The serialized structured field parameter string.
      #
      def self.serialize_parameters(parameters)
        params_str = +""
        parameters.each do |key, value|
          params_str << case value
          when Integer
            ";#{key}=#{value}"
          when String
            ";#{key}=\"#{value}\""
          else
            ";#{key}=#{value}"
          end
        end
        params_str
      end

      # Serializes parsed Starry items to their string representations
      # without going through the generic Starry.serialize_item path.
      #
      # For simple items (no parameters): builds '"value"' directly.
      # For items with parameters: falls back to Starry.serialize_item.
      #
      # @param items [Array<Starry::Item>] parsed items from signature-input
      # @return [Array<String>] serialized component identifiers
      def self.serialize_parsed_items(items)
        items.map do |item|
          if item.parameters.empty?
            "\"#{item.value}\""
          else
            Starry.serialize_item(item)
          end
        end
      end

      def self.serialize_dictionary(hsh)
        Starry.serialize_dictionary(hsh)
      end

      def self.serialize(obj)
        Starry.serialize(obj)
      end

      def self.parse_item(item)
        Starry.parse_item(item)
      end
    end
  end
end
