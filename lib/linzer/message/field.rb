# frozen_string_literal: true

module Linzer
  class Message
    class Field
      module IdentifierMethods
        def initialize(field_name:)
          @item = Identifier::Parser.parse(field_name) rescue nil
          super
        end

        attr_reader :item

        def derived?
          item&.value&.start_with?("@")
        end

        def serialize
          raise Error, "Invalid component identifier: '#{field_name}'!" unless item
          Starry.serialize(@item)
        end
      end

      # Excluded from coverage as obviously both branches cannot be covered
      # on a single test run.
      # :nocov:
      if Gem::Version.new(RUBY_VERSION) < Gem::Version.new("3.2.0")
        class Identifier < Struct.new(:field_name, keyword_init: true); end
      else
        class Identifier < Data.define(:field_name); end
      end
      # :nocov:

      Identifier.include Message::Field::IdentifierMethods

      class Identifier
        class << self
          def serialize(component)
            new(field_name: component).serialize
          end

          def serialize_components(components)
            components.map(&method(:serialize))
          end

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
