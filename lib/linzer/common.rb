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
    def signature_base(message, serialized_components, parameters, field_ids: nil)
      buf = +""

      if field_ids
        i = 0
        len = serialized_components.size
        while i < len
          buf << serialized_components[i] << ": " << String(message[field_ids[i]]) << "\n"
          i += 1
        end
      else
        serialized_components.each do |component|
          buf << signature_base_line(component, message) << "\n"
        end
      end

      buf << signature_params_line(serialized_components, parameters)

      buf
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
    SERIALIZED_SIGNATURE_PARAMS = HTTP::StructuredField.serialize("@signature-params").freeze
    private_constant :SERIALIZED_SIGNATURE_PARAMS

    def signature_params_line(serialized_components, parameters)
      params_str = HTTP::StructuredField.serialize_parameters(parameters)
      components_str = serialized_components.join(" ")

      "#{SERIALIZED_SIGNATURE_PARAMS}: (#{components_str})#{params_str}"
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
    def validate_components(message, components, field_ids: nil)
      has_params = false
      missing = "Cannot verify signature. Missing component in message"
      invalid = "Invalid component in signature input"

      if field_ids
        i = 0
        len = components.size
        while i < len
          c = components[i]
          raise Error, invalid if c.include?("@signature-params")
          has_params = true if !has_params && c.include?(";")
          raise Error, "#{missing}: \"#{c}\"" unless message.field?(field_ids[i])
          i += 1
        end
      else
        components.each do |c|
          raise Error, invalid if c.include?("@signature-params")
          has_params = true if !has_params && c.include?(";")
          raise Error, "#{missing}: \"#{c}\"" unless message.field?(c)
        end
      end

      validate_uniqueness(components) if has_params || components.size != components.uniq.size
    end

    # Validates that there are no duplicate components.
    #
    # Components are considered duplicates if they have the same value
    # and parameters, even if serialized differently.
    #
    # @param components [Array<String>] Component identifiers to check
    # @raise [Error] If any component appears more than once
    def validate_uniqueness(components)
      duplicated = "Invalid signature. Duplicated component in signature input."

      # String-level duplicates are always invalid
      raise Error, duplicated if components.size != components.uniq.size

      # If any component has parameters, also check for semantic duplicates
      # (e.g. ;bs;req vs ;req;bs are semantically equal but different strings)
      return unless components.any? { |c| c.include?(";") }

      uniq_components =
        components
          .partition { |c| c.start_with?("@") }
          .flat_map
          .with_index do |group, idx|
            group
              .map  { |comp| HTTP::StructuredField.parse_item(idx.zero? ? comp[1..] : comp) }
              .uniq { |comp| [comp.value, comp.parameters] }
          end

      raise Error, duplicated if components.count != uniq_components.count
    end
  end
end
