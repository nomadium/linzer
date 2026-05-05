# frozen_string_literal: true

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
    end
  end
end
