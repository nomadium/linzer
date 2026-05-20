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
      InnerList  = Starry::InnerList
      Item       = Starry::Item

      # Parses an RFC 8941 Structured Field Dictionary.
      #
      # @param str [String] the serialized dictionary value
      # @param field_name [String, nil] optional field name for contextual errors
      # @return [Hash<String, Object>] parsed structured field dictionary
      # @raise [Linzer::Error] if the field cannot be parsed
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.parse_dictionary(str, field_name: nil)
        Starry.parse_dictionary(str)
      # rescue Starry::ParseError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        cannot_parse = "Cannot parse %sfield!"
        raise Error,
              cannot_parse % [field_name ? "\"#{field_name}\" " : nil],
              cause: ex
      end

      # Parses an RFC 8941 Structured Field Item.
      #
      # @param item [String] serialized structured field item
      # @return [Starry::Item] parsed structured field item
      # @raise [Linzer::Error] if the item is invalid or unparseable
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.parse_item(item)
        Starry.parse_item(item)
      # rescue Starry::ParseError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        raise Error, "Invalid/unparseable HTTP field item", cause: ex
      end

      # Parses an RFC 8941 Structured Field List.
      #
      # @param list [String] serialized structured field list
      # @return [Array<Object>] parsed structured field list members
      # @raise [Linzer::Error] if the list is invalid or unparseable
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.parse_list(list)
        Starry.parse_list(list)
      # rescue Starry::ParseError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        raise Error, "Invalid/unparseable HTTP field list", cause: ex
      end

      # Serializes a dictionary into RFC 8941 Structured Field format.
      #
      # @param hsh [Hash] structured field dictionary
      # @return [String] serialized structured field dictionary
      # @raise [Linzer::Error] if the dictionary cannot be serialized
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.serialize_dictionary(hsh)
        Starry.serialize_dictionary(hsh)
      # rescue Starry::SerializeError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        raise Error, ex.message, cause: ex
      end

      # Serializes a list into RFC 8941 Structured Field format.
      #
      # @param arr [Array] structured field list members
      # @return [String] serialized structured field list
      # @raise [Linzer::Error] if the list cannot be serialized
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.serialize_list(arr)
        Starry.serialize_list(arr)
      # rescue Starry::SerializeError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        raise Error, ex.message, cause: ex
      end

      # Serializes an object into RFC 8941 Structured Field format.
      #
      # @param obj [Object] structured field value
      # @return [String] serialized structured field value
      # @raise [Linzer::Error] if the object cannot be serialized
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.serialize(obj)
        Starry.serialize(obj)
      rescue Starry::SerializeError => ex
        raise Error, ex.message, cause: ex
      end

      # Serializes a Structured Field Item into RFC 8941 format.
      #
      # This helper serializes a single Structured Field Item, such as
      # a string, integer, token, boolean, date, byte sequence, or
      # an already constructed {Starry::Item}.
      #
      # @param item [Object] structured field item value
      # @return [String] serialized structured field item
      # @raise [Linzer::Error] if the item cannot be serialized
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.serialize_item(item)
        Starry.serialize_item(item)
      rescue Starry::SerializeError => ex
        raise Error, ex.message, cause: ex
      end

      # Serializes Structured Field Parameters into RFC 8941 format.
      #
      # Parameters are serialized according to the Structured Fields
      # parameter syntax defined in RFC 8941 Section 3.1.2.
      #
      # @param parameters [Hash{String,Symbol => Object}] parameter names
      #   and values
      # @return [String] serialized structured field parameters
      # @raise [Linzer::Error] if the parameters cannot be serialized
      #
      # @see https://www.rfc-editor.org/rfc/rfc8941 RFC 8941
      def self.serialize_parameters(parameters)
        Starry.serialize_parameters(parameters)
      # rescue Starry::SerializeError => ex
      # https://github.com/takemar/starry/pull/4
      rescue => ex
        raise Error, ex.message, cause: ex
      end
    end
  end
end
