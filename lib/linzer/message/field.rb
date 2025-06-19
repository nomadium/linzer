# frozen_string_literal: true

module Linzer
  class Message
    class Field
      module IdentifierMethods
        def parse(field_name)
          case
          when field_name.match?(/";/), field_name.start_with?('"')
            Starry.parse_item(field_name)
          when field_name.match?(/;/)
            parse_unserialized_input(field_name)
          when field_name.start_with?("@"), field_name.match?(/^[a-z]/)
            Starry.parse_item(Starry.serialize(field_name))
          else
            raise Error, "Invalid component identifier: '#{field_name}'!"
          end
        rescue Starry::ParseError => ex
          parse_error = "Failed to parse component identifier: '#{field_name}'!"
          raise Error, parse_error, cause: ex
        end
        module_function :parse

        def initialize(field_name:)
          @item = IdentifierMethods.parse(field_name) rescue nil
          super
        end

        attr_reader :item

        def derived?
          field_name.start_with?("@", '"@')
        end

        def serialize
          raise Error, "Invalid component identifier: '#{field_name}'!" unless @item
          Starry.serialize(@item)
        end

        def serialize2
          # binding.irb
          raise Error, "Invalid component identifier: '#{field_name}'!" unless @item
          serialized_name = Starry.serialize_bare_item(@item.value)
          serialized_name.prepend("@") if derived?
          serialized_params = Starry.serialize_parameters(@item.parameters)
          '"%s"%s' % [serialized_name, serialized_params]
        end

        private

        # XXX: this is to ugly, fix!
        def parse_unserialized_input(field_name)
          field, *params = field_name.split(/;/)
          item = Starry.parse_item("foo")
          item.value = field
          np = params.map do |p|
            p.split("=").size == 2 ? Hash[*p.split("=")] : { p => true }
          end
          item.parameters = np.shift
          item
        end
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
