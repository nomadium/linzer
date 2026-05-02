# frozen_string_literal: true

module Linzer
  # Handles HTTP message signing according to RFC 9421.
  #
  # This module provides the core signing functionality. It creates signatures
  # by computing a signature base from the message components and signing it
  # with the provided key.
  #
  # @example Direct usage (prefer Linzer.sign for convenience)
  #   message = Linzer::Message.new(request)
  #   components = %w[@method @path content-type]
  #   signature = Linzer::Signer.sign(key, message, components)
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.1 RFC 9421 Section 3.1
  module Signer
    # Default label used for signatures when none is specified.
    # @return [String]
    DEFAULT_LABEL = "sig1"

    class << self
      include Common

      # Signs an HTTP message.
      #
      # Creates a signature by:
      # 1. Serializing the component identifiers
      # 2. Building the signature base from the message and parameters
      # 3. Signing the signature base with the key
      # 4. Returning a Signature object with the result
      #
      # @param key [Linzer::Key] The private key to sign with. Must respond to
      #   `#sign` and should contain private key material.
      # @param message [Linzer::Message] The HTTP message to sign
      # @param components [Array<String>] Component identifiers to include in
      #   the signature. Can be header names (e.g., `"content-type"`) or derived
      #   components (e.g., `"@method"`, `"@path"`). May include parameters
      #   (e.g., `"content-type";bs` for binary-wrapped).
      # @param options [Hash] Additional signature parameters
      # @option options [Integer] :created Unix timestamp for signature creation.
      #   Defaults to the current UTC time.
      # @option options [String] :keyid Key identifier. If not provided, uses
      #   the key's `key_id` if available.
      # @option options [String] :label The signature label (defaults to "sig1").
      #   Multiple signatures on a message must have distinct labels.
      # @option options [String] :nonce A unique nonce value to prevent replay
      # @option options [String] :tag Application-specific tag
      # @option options [Integer] :expires Unix timestamp when signature expires
      # @option options [String] :alg Algorithm identifier (usually inferred from key)
      #
      # @return [Linzer::Signature] The generated signature, ready to be attached
      #   to the message via {Signature#to_h}
      #
      # @raise [SigningError] If the message, key, or components are invalid
      # @raise [SigningError] If required components are missing from the message
      # @raise [SigningError] If components are duplicated
      # @raise [SigningError] If `@signature-params` is included in components
      #
      # @example Basic signing
      #   signature = Linzer::Signer.sign(key, message, %w[@method @path])
      #
      # @example With all options
      #   signature = Linzer::Signer.sign(key, message, %w[@method @path date],
      #     created: Time.now.to_i,
      #     keyid: "my-key-2024",
      #     label: "request-sig",
      #     nonce: SecureRandom.hex(16),
      #     tag: "my-app"
      #   )
      def sign(key, message, components, options = {})
        serialized_components = FieldId.serialize_components(Array(components))
        validate key, message, serialized_components

        # Parse component identifiers once and reuse throughout the pipeline
        parsed_items = serialized_components.map { |c| Starry.parse_item(c) }

        parameters = populate_parameters(key, options)
        signature_base = signature_base(message, serialized_components, parameters, parsed_items: parsed_items)

        raw_signature = key.sign(signature_base)
        label = options[:label] || DEFAULT_LABEL

        # Build the Signature directly, bypassing the serialize→parse round-trip
        headers = serialize(raw_signature, serialized_components, parameters, label, parsed_items: parsed_items)

        Linzer::Signature.from_components(
          components:    serialized_components,
          raw_signature: raw_signature,
          label:         label,
          parameters:    parameters,
          parsed_items:  parsed_items,
          headers:       headers
        )
      end

      # Returns the default signature label.
      #
      # @return [String] The default label ("sig1")
      def default_label
        DEFAULT_LABEL
      end

      private

      # Validates signing inputs.
      # @raise [SigningError] If any input is invalid
      def validate(key, message, components)
        msg = "Message cannot be signed with null %s"
        raise SigningError, msg % "value"     if message.nil?
        raise SigningError, msg % "key"       if key.nil?
        raise SigningError, msg % "component" if components.nil?

        begin
          validate_components message, components
        rescue Error => ex
          raise SigningError, ex.message, cause: ex
        end
      end

      # Builds the signature parameters hash from options and key.
      # @return [Hash] The populated parameters
      def populate_parameters(key, options)
        parameters = {}

        parameters[:created] = options[:created] || Time.now.getutc.to_i

        key_id = options[:keyid] || (key.key_id if key.respond_to?(:key_id))
        parameters[:keyid] = key_id             unless key_id.nil?

        (options.keys - %i[created keyid label]).each { |k| parameters[k] = options[k] }

        parameters
      end

      # Serializes the signature into HTTP header format.
      # @return [Hash] Hash with "signature" and "signature-input" keys
      def serialize(signature, components, parameters, label, parsed_items: nil)
        items = parsed_items || components.map { |c| Starry.parse_item(c) }
        {
          "signature" => Starry.serialize({label => signature}),
          "signature-input" =>
            Starry.serialize(label =>
              Starry::InnerList.new(items, parameters))
        }
      end
    end
  end
end
