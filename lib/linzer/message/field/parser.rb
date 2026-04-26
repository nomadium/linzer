# frozen_string_literal: true

module Linzer
  class Message
    class Field
      class Identifier
        # Parses component identifier strings into structured items.
        #
        # Handles various formats:
        # - Simple names: `"content-type"`
        # - Derived components: `"@method"`
        # - With parameters: `"content-type";bs`, `"example-dict";key="a"`
        # - Already serialized: `'"content-type"'`
        #
        # @api private
        module Parser
          extend self

          # Parses a field name into a structured item.
          #
          # @param field_name [String] The component identifier string
          # @return [Starry::Item] The parsed structured field item
          # @raise [Error] If the field name cannot be parsed
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

          private

          # Parses an unserialized component identifier with parameters.
          #
          # Splits on +;+ to separate the field name from parameters,
          # then serializes the field name and collects parameters.
          #
          # @param field_name [String] e.g. +"content-type;bs"+ or
          #   +"example-dict;key=\"a\""+
          # @return [Starry::Item] the parsed item with parameters
          def parse_unserialized_input(field_name)
            field, *raw_params = field_name.split(";")
            item               = Starry.parse_item(Starry.serialize(field))
            item.parameters    = collect_parameters(raw_params)
            item
          end

          # Parses raw parameter strings into a merged Hash.
          #
          # Handles both boolean parameters (+";bs"+ → +{"bs" => true}+)
          # and key-value parameters (+";key=\"a\""+ → +{"key" => "a"}+).
          #
          # @param str [Array<String>] raw parameter strings
          # @return [Hash] merged parameter hash
          def collect_parameters(str)
            params = str.map do |param|
              if (tokens = param.split("=")) == [param] # e.g.: ";bs"
                {param => true}
              else
                Hash[*tokens.first(2)]                  # e.g.: ";key=\"foo\""
                  .transform_values! { |v| Starry.parse_item(v).value }
              end
            end
            params.reduce({}, :merge)
          end
        end
      end
    end
  end
end
