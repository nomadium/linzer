# frozen_string_literal: true

module Linzer
  class Message
    class Field
      class Identifier
        module Parser
          extend self

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

          def parse_unserialized_input(field_name)
            field, *raw_params = field_name.split(";")
            item               = Starry.parse_item(Starry.serialize(field))
            item.parameters    = collect_parameters(raw_params)
            item
          end

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
