# frozen_string_literal: true

module Linzer
  class Verifier
    def initialize(pubkeys = nil)
      @pubkeys = Hash(pubkeys)
    end

    attr_reader :pubkeys

    # XXX: probably all this validation can be moved to the Message class
    def verify(message)
      validate message

      signature_input = parse_field(message, "signature-input")
      signature = parse_field(message, "signature")

      # XXX: this is a self-imposed limitation, fix later
      reject_multiple(signature)

      choosen_signature = signature.keys[0]
      if !signature_input.key?(choosen_signature)
        raise Error.new "Signature \"#{choosen_signature}\" is not found."
      end

      covered_components = signature_input[choosen_signature].to_a
      signature_parameters = signature_input[choosen_signature].parameters

      signature_value = signature[choosen_signature].value
      # XXX to-do: have a mechanism to inspect components and parameters

      check_key_presence signature_parameters
      check_components message, covered_components

      signature_base = build_signature_base(message, signature_input)

      # XXX to-do: get rid of this hard-coded SHA512 values, support more algs
      key = pubkeys[signature_parameters["keyid"]]
      if !key.verify_pss("SHA512", signature_value, signature_base, salt_length: :auto, mgf1_hash: "SHA512")
        raise Error.new "Failed to verify message: Invalid signature."
      end

      true
    end

    private

    def validate(message)
      raise Error.new "Message to verify cannot be null" if message.nil?
      raise Error.new "Message to verify cannot be empty" if message.empty?
      raise Error.new "Message signature cannot be incomplete" unless message.header?("signature-input")
      raise Error.new "Message has no signature to verify" unless message.header?("signature")
    end

    def parse_field(message, field_name)
      Starry.parse_dictionary(message[field_name])
    rescue Starry::ParseError => _
      raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
    end

    def reject_multiple(hsh)
      msg = "Messages with more than 1 signatures are not supported"
      raise Error.new msg if hsh.keys.size > 1
    end

    def check_key_presence(parameters)
      msg = "Cannot verify signature. Key not found"

      key_id = parameters["keyid"]
      raise Error.new msg if key_id.nil?
      msg += ": \"#{key_id}\"" if !key_id.empty?

      raise Error.new msg unless pubkeys.key?(key_id)
    end

    def check_components(message, components)
      msg = "Cannot verify signature. Missing component in message: "
      components
        .map(&:value)
        .reject { |component| message[component] }
        .shift
        .tap do |component|
          if component
            msg += "\"#{component}\""
            raise Error.new msg
          end
        end
    end

    def build_signature_base(message, signature_input)
      signature_base = +""
      signature_params = ""
      signature_input.each do |k, l|
        signature_params = l.to_s
        l.value.each { |c| signature_base << "\"#{c.value}\": #{message[c.value]}\n" }
      end
      signature_base << "\"@signature-params\": #{signature_params}"
      signature_base
    end
  end
end
