# frozen_string_literal: true

module Linzer
  module Common
    def signature_base(message, serialized_components, parameters)
      signature_base = serialized_components.each_with_object(+"") do |component, base|
        base << "%s\n" % signature_base_line(component, message)
      end

      identifiers = serialized_components.map { |c| Starry.parse_item(c) }

      signature_params =
        Starry.serialize([Starry::InnerList.new(identifiers, parameters)])

      # signature_base << signature_base_line(Starry.serialize("@signature-params"), signature_params)
      signature_base << "%s: %s" % [Starry.serialize("@signature-params"), signature_params]
      signature_base
    end
    module_function :signature_base

    private

    def signature_base_line(component, message)
      identifier = if component.include?(";")
        binding.irb
        field_name = Starry.parse_item(component)
        # Message::Field::Identifier.new(field_name: field_name.value).serialize
        Starry.serialize(Message::Field::Identifier.new(field_name: component).item)
      else
        component
      end
      "%s: %s" % [identifier, message[identifier]]
    end

    def signature_base_line2(component, value)
      # Starry.serialize(Starry.parse_item('"' + Starry.parse_item(component).value.split(";")[0] + '"' + ";" + Starry.parse_item(component).value.split(";")[1..].shift))
      # binding.irb
      identifier = if !component.include?(";")
        component
      else
        # rubocop:disable Style/IfInsideElse
        if component.start_with?('"')
          component
        else
          binding.irb
          Message::Field::Identifier.new(field_name: component)
            .serialize
        end
        # rubocop:enable Style/IfInsideElse
      end
      "%s: %s" % [identifier, value]
    end
    module_function :signature_base_line

    def validate_components(message, components)
      if components.include?("@signature-params") ||
          components.any? { |c| c.start_with?("@signature-params;") }
        raise Error.new "Invalid component in signature input"
      end

      msg = "Cannot verify signature. Missing component in message: %s"
      components.each do |c|
        raise Error.new msg % "\"#{c}\"" unless message.field?(c)
      end

      validate_uniqueness components
    end

    def validate_uniqueness(components)
      msg = "Invalid signature. Duplicated component in signature input."

      uniq_components =
        components
          .partition { |c| c.start_with?("@") }
          .flat_map
          .with_index do |group, idx|
            group
              .map  { |comp| Starry.parse_item(idx.zero? ? comp[1..] : comp) }
              .uniq { |comp| [comp.value, comp.parameters] }
          end

      raise Error.new msg if components.count != uniq_components.count
    end
  end
end
