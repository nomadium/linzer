# frozen_string_literal: true

module Linzer
  class Message
    class Field
      module IdentifierMethods
        def serialize
          item = parse_field_name
          component_name = Starry.serialize_bare_item(item.value)
          component_name.prepend("@") if derived?
          parameters     = Starry.serialize_parameters(item.parameters)
          '"%s"%s' % [component_name, parameters]
        end

        alias_method :to_s, :serialize

        private

        def parse_field_name
          Starry.parse_item(derived? ? field_name[1..] : field_name)
        rescue Starry::ParseError => ex
          raise Error, "Invalid component identifier: '#{field_name}'!", cause: ex
        end

        def derived?
          field_name.start_with?("@")
        end
      end

      # Excluded as obviously, both branches cannot be covered on a single run
      # :nocov:
      if Gem::Version.new(RUBY_VERSION) < Gem::Version.new("3.2.0")
        class Identifier < Struct.new(:field_name); end
      else
        class Identifier < Data.define(:field_name); end
      end
      # :nocov:

      Identifier.include Message::Field::IdentifierMethods
    end
  end
end
