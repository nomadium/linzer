# frozen_string_literal: true

module Linzer
  module Common
    def signature_base(message, serialized_components, parameters)
      signature_base =
        serialized_components.each_with_object(+"") do |component, base|
          base << "%s\n" % signature_base_line(component, message)
        end

      signature_base << signature_params_line(serialized_components, parameters)

      signature_base
    end
    module_function :signature_base

    def signature_base_line(component, message)
      field_id = FieldId.new(field_name: component)
      "%s: %s" % [field_id.serialize, message[field_id]]
    end
    module_function :signature_base_line

    def signature_params_line(serialized_components, parameters)
      identifiers = serialized_components.map { |c| Starry.parse_item(c) }

      signature_params =
        Starry.serialize([Starry::InnerList.new(identifiers, parameters)])

      "%s: %s" % [Starry.serialize("@signature-params"), signature_params]
    end
    module_function :signature_params_line

    private

    def validate_components(message, components)
      if components.include?('"@signature-params"') ||
          components.any? { |c| c.start_with?('"@signature-params"') }
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
