# frozen_string_literal: true

module Linzer
  module Signer
    DEFAULT_LABEL = "sig1"

    class << self
      include Common

      def sign(key, message, components, options = {})
        validate key, message, components

        parameters = populate_parameters(key, options)
        signature_base = signature_base(message, components, parameters)

        signature = key.sign(signature_base)
        label = options[:label] || DEFAULT_LABEL

        Linzer::Signature.build(serialize(signature, components, parameters, label))
      end

      def default_label
        DEFAULT_LABEL
      end

      private

      def validate(key, message, components)
        msg = "Message cannot be signed with null %s"
        raise Error, msg % "value"     if message.nil?
        raise Error, msg % "key"       if key.nil?
        raise Error, msg % "component" if components.nil?

        validate_components message, components
      end

      def populate_parameters(key, options)
        parameters = {}

        parameters[:created] = options[:created] || Time.now.getutc.to_i

        key_id = options[:keyid] || (key.key_id if key.respond_to?(:key_id))
        parameters[:keyid] = key_id             unless key_id.nil?

        (options.keys - %i[created keyid label]).each { |k| parameters[k] = options[k] }

        parameters
      end

      def serialize(signature, components, parameters, label)
        {
          "signature" => Starry.serialize({label => signature}),
          "signature-input" =>
            Starry.serialize({label =>
              Starry::InnerList.new(components, parameters)})
        }
      end
    end
  end
end
