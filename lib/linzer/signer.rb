# frozen_string_literal: true

module Linzer
  module Signer
    DEFAULT_LABEL = "sig1"

    class << self
      def sign(key, message, components, options = {})
        validate key, message, components

        parameters = populate_parameters(key, options)
        signature_base = message.signature_base(components, parameters)

        signature = _sign(key, signature_base, options)
        label = options[:label] || DEFAULT_LABEL

        Linzer::Signature.build(serialize(signature, components, parameters, label))
      end

      def default_label
        DEFAULT_LABEL
      end

      private

      def validate(key, message, components)
        raise Error.new "Message to sign cannot be null"           if message.nil?
        raise Error.new "Message cannot be signed with a null key" if key.nil?

        if components.include?("@signature-params")
          raise Error.new "Invalid component in signature input"
        end

        component_missing = 'Cannot sign message: component "%s" is not present in message'
        components.each do |c|
          raise Error.new component_missing % c unless message.field? c
        end
      end

      def populate_parameters(key, options)
        parameters = {}

        parameters[:created] = options[:created] || Time.now.getutc.to_i

        key_id = options[:keyid] || (key.key_id if key.respond_to?(:key_id))
        parameters[:keyid] = key_id             unless key_id.nil?

        (options.keys - %i[created keyid label]).each { |k| parameters[k] = options[k] }

        parameters
      end

      def _sign(key, data, options)
        # signature = key.sign_pss("SHA512", signature_base, salt_length: 64, mgf1_hash: "SHA512")
        key.sign("SHA512", data)
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
