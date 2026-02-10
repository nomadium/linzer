# frozen_string_literal: true

module Linzer
  # Shared functionality for signature base computation and validation.
  #
  # This module contains the core logic for building the canonical signature
  # base string that gets signed/verified, as defined in RFC 9421 Section 2.5.
  #
  # @api private
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5 RFC 9421 Section 2.5
  module Common
    # Computes the signature base string for an HTTP message.
    #
    # The signature base is a canonical string representation of the covered
    # components, formatted according to RFC 9421. This is the string that
    # gets cryptographically signed.
    #
    # @param message [Message] The HTTP message
    # @param serialized_components [Array<String>] Serialized component identifiers
    # @param parameters [Hash] Signature parameters (created, keyid, etc.)
    # @return [String] The signature base string
    #
    # @example Signature base format
    #   # Each covered component on its own line:
    #   # "@method": POST
    #   # "@path": /foo
    #   # "content-type": application/json
    #   # "@signature-params": ("@method" "@path" "content-type");created=1618884473
    def signature_base(message, serialized_components, parameters)
      signature_base =
        serialized_components.each_with_object(+"") do |component, base|
          base << "%s\n" % signature_base_line(component, message)
        end

      signature_base << signature_params_line(serialized_components, parameters)

      signature_base
    end
    module_function :signature_base

    # Builds a single line of the signature base for a component.
    #
    # @param component [String] The serialized component identifier
    # @param message [Message] The HTTP message
    # @return [String] The formatted line (e.g., '"@method": POST')
    def signature_base_line(component, message)
      field_id = FieldId.new(field_name: component)
      "%s: %s" % [field_id.serialize, message[field_id]]
    end
    module_function :signature_base_line

    # Builds the @signature-params line for the signature base.
    #
    # This is always the last line of the signature base and contains
    # the covered components list and signature parameters.
    #
    # @param serialized_components [Array<String>] The covered components
    # @param parameters [Hash] Signature parameters
    # @return [String] The formatted @signature-params line
    def signature_params_line(serialized_components, parameters)
      identifiers = serialized_components.map { |c| Starry.parse_item(c) }

      signature_params =
        Starry.serialize([Starry::InnerList.new(identifiers, parameters)])

      "%s: %s" % [Starry.serialize("@signature-params"), signature_params]
    end
    module_function :signature_params_line

    private

    # Validates that all specified components are valid and present.
    #
    # @param message [Message] The HTTP message
    # @param components [Array<String>] Component identifiers to validate
    # @raise [Error] If @signature-params is in the components
    # @raise [Error] If any component is missing from the message
    # @raise [Error] If any component is duplicated
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

    # Validates that there are no duplicate components.
    #
    # Components are considered duplicates if they have the same value
    # and parameters, even if serialized differently.
    #
    # @param components [Array<String>] Component identifiers to check
    # @raise [Error] If any component appears more than once
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
