# frozen_string_literal: true

module Linzer
  class Message
    class Field
      module IdentifierMethods
        def parse(field_name)
          Starry
            .parse_item(field_name.start_with?("@") ? field_name[1..] : field_name)
        rescue Starry::ParseError => ex
          raise Error, "Invalid component identifier: '#{field_name}'!", cause: ex
        end
        module_function :parse

        def initialize(field_name:)
          @item = IdentifierMethods.parse(field_name) rescue nil
          super
        end

        attr_reader :item

        def derived?
          field_name.start_with?("@") || field_name.start_with?('"@')
        end

        def serialize
          raise Error, "Invalid component identifier: '#{field_name}'!" unless @item
          serialized_name = Starry.serialize_bare_item(@item.value)
          serialized_name.prepend("@") if derived?
          serialized_params = Starry.serialize_parameters(@item.parameters)
          '"%s"%s' % [serialized_name, serialized_params]
        end

        alias_method :to_s, :serialize
      end

      # Excluded from coverage, as obviously both branches cannot be covered
      # on a single tests run.
      # :nocov:
      if Gem::Version.new(RUBY_VERSION) < Gem::Version.new("3.2.0")
        class Identifier < Struct.new(:field_name, keyword_init: true); end
      else
        class Identifier < Data.define(:field_name); end
      end
      # :nocov:

      Identifier.include Message::Field::IdentifierMethods
    end
  end
end
