# frozen_string_literal: true

module Linzer
  class Message
    # Handles HTTP message field identification and serialization.
    #
    # Fields represent HTTP header fields and derived components that can
    # be included in signatures. This class handles parsing and serialization
    # of component identifiers according to RFC 9421.
    #
    # @api private
    class Field
      # Methods mixed into the Identifier class for field name handling.
      # @api private
      module IdentifierMethods
        # Initializes the identifier by parsing the field name.
        # @param field_name [String] The component identifier string
        def initialize(field_name:)
          @item = Identifier::Parser.parse(field_name) rescue nil
          super
        end

        # @return [Starry::Item, nil] The parsed structured field item
        attr_reader :item

        # Checks if this is a derived component (starts with @).
        # @return [Boolean] true if derived (e.g., @method, @path)
        def derived?
          item&.value&.start_with?("@")
        end

        # Serializes the component identifier.
        # @return [String] The serialized identifier (e.g., '"@method"')
        # @raise [Error] If the component identifier is invalid
        def serialize
          raise Error, "Invalid component identifier: '#{field_name}'!" unless item
          @serialized || Starry.serialize(@item)
        end
      end

      # Component identifier for HTTP message fields.
      #
      # Uses Data.define on Ruby 3.2+ for immutability, falls back to Struct
      # on older versions.
      #
      # @api private
      # :nocov:
      if Gem::Version.new(RUBY_VERSION) < Gem::Version.new("3.2.0")
        class Identifier < Struct.new(:field_name, keyword_init: true); end
      else
        class Identifier < Data.define(:field_name); end
      end
      # :nocov:

      Identifier.include Message::Field::IdentifierMethods

      # Lightweight FieldId for simple components (no parameters).
      # Bypasses Starry parsing entirely. Duck-types with Identifier
      # for use in the adapter's [] method.
      # @api private
      class FastIdentifier
        def initialize(serialized, item)
          @field_name = serialized
          @item       = item
          @serialized = serialized
          freeze
        end

        attr_reader :field_name, :item

        def derived?
          @item.value.start_with?("@")
        end

        def serialize
          @serialized
        end
      end

      class Identifier
        class << self
          # Serializes a single component identifier.
          # @param component [String] The component name
          # @return [String] The serialized identifier
          def serialize(component)
            new(field_name: component).serialize
          end

          # Serializes an array of component identifiers.
          # @param components [Array<String>] Component names
          # @return [Array<String>] Serialized identifiers
          def serialize_components(components)
            components.map(&method(:serialize))
          end

          # Serializes an array of component identifiers, returning both
          # the serialized strings and the FieldId objects for reuse.
          # @param components [Array<String>] Component names
          # @return [Array(Array<String>, Array<Identifier>)] Serialized strings and FieldId objects
          def serialize_components_with_field_ids(components)
            serialized = Array.new(components.size)
            field_ids  = Array.new(components.size)

            components.each_with_index do |c, i|
              if c.include?(";") || c.include?('"')
                # Complex component with parameters or already serialized:
                # fall back to full Starry parsing
                fid = new(field_name: c)
                field_ids[i]  = fid
                serialized[i] = fid.serialize
              else
                # Simple component (e.g. "@method", "content-type"):
                # build the Item and serialized string directly,
                # bypassing Starry.parse_item + Starry.serialize
                quoted = "\"#{c}\""
                item   = Starry::Item.new(c, {})
                field_ids[i]  = FastIdentifier.new(quoted, item)
                serialized[i] = quoted
              end
            end

            [serialized, field_ids]
          end

          # Deserializes component identifiers back to names.
          # @param components [Array<String>] Serialized identifiers
          # @return [Array<String>] Component names
          def deserialize_components(components)
            components.map do |c|
              item = Starry.parse_item(c)
              item.parameters.empty? ? item.value : Starry.serialize(item)
            end
          end
        end
      end
    end
  end
end
