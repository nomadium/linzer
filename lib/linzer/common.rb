# frozen_string_literal: true

module Linzer
  module Common
    def signature_base(message, components, parameters)
      signature_base = components.each_with_object(+"") do |component, base|
        base << "\"#{component}\": #{message[component]}\n"
      end

      signature_params =
        Starry.serialize([Starry::InnerList.new(components, parameters)])

      signature_base << "\"@signature-params\": #{signature_params}"
      signature_base
    end

    def validate_components(message, components)
      if components.include?("@signature-params")
        raise Error.new "Invalid component in signature input"
      end
      msg = "Cannot verify signature. Missing component in message: %s"
      components.each { |c| raise Error.new msg % "\"#{c}\"" unless message.field?(c)  }
      msg = "Invalid signature. Duplicated component in signature input."
      raise Error.new msg if components.size != components.uniq.size
    end
  end
end
