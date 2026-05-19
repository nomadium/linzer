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
      # Serializes HTTP Structured Field parameters according to RFC 8941.
      #
      # This is primarily used for HTTP Message Signature parameters defined
      # by RFC 9421.
      #
      # Serialization is delegated to `Starry.serialize_parameters` to ensure
      # proper RFC-compliant encoding and quoting behavior for structured
      # field values.
      #
      # @example Serialize signature parameters
      #   StructuredField.serialize_parameters(
      #     created: 1700000000,
      #     keyid: "my-key"
      #   )
      #   # => ';created=1700000000;keyid="my-key"'
      #
      # @param parameters [Hash{Symbol,String => Object}]
      #   The parameters to serialize as structured field parameters.
      #
      # @return [String]
      #   The serialized structured field parameter string.
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      # @see https://www.rfc-editor.org/rfc/rfc9421 RFC 9421
      def self.serialize_parameters(parameters)
        Starry.serialize_parameters(parameters)
      end
    end
  end
end
