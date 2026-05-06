# frozen_string_literal: true

module Linzer
  # Represents an HTTP message signature as defined in RFC 9421.
  #
  # A Signature encapsulates:
  # - The raw signature bytes
  # - The covered components (fields included in the signature)
  # - The signature parameters (created, keyid, etc.)
  # - The signature label (for identifying multiple signatures)
  #
  # Signatures are immutable once created. Use {.build} to create instances
  # from HTTP headers, or receive them from {Signer.sign}.
  #
  # @example Building a signature from HTTP headers
  #   headers = {
  #     "signature-input" => 'sig1=("@method" "@path");created=1618884473',
  #     "signature" => "sig1=:base64encodedvalue...:"
  #   }
  #   signature = Linzer::Signature.build(headers)
  #
  # @example Attaching a signature to a request
  #   signature = Linzer.sign(key, message, components)
  #   signature.to_h.each { |name, value| request[name] = value }
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-4 RFC 9421 Section 4
  class Signature
    # @api private
    # Use {.build} or {.from_components} to create Signature instances.
    def initialize(metadata, value, label, parameters = {}, parsed_items: nil, headers: nil)
      @metadata     = metadata.clone.freeze
      @value        = value.clone.freeze
      @parameters   = parameters.clone.freeze
      @label        = label.clone.freeze
      @parsed_items = parsed_items&.freeze
      @headers      = headers&.freeze
      freeze
    end

    # @!attribute [r] metadata
    #   @return [Array<String>] The serialized component identifiers
    #   @see #serialized_components
    attr_reader :metadata

    # @!attribute [r] value
    #   @return [String] The raw signature bytes (binary string)
    attr_reader :value

    # @!attribute [r] parameters
    #   @return [Hash] The signature parameters (created, keyid, nonce, etc.)
    #   @note Keys are strings, not symbols
    attr_reader :parameters

    # @!attribute [r] label
    #   @return [String] The signature label (e.g., "sig1")
    attr_reader :label

    # @!method serialized_components
    #   Returns the serialized component identifiers.
    #   @return [Array<String>] Component identifiers in serialized form
    #     (e.g., `['"@method"', '"content-type"']`)
    alias_method :serialized_components, :metadata

    # @!method bytes
    #   Returns the raw signature bytes.
    #   @return [String] The signature value as binary string
    alias_method :bytes, :value

    # Returns the deserialized component identifiers.
    #
    # Unlike {#serialized_components}, this returns the components in a more
    # human-readable form.
    #
    # @return [Array<String>] Component identifiers (e.g., `["@method", "content-type"]`)
    def components
      FieldId.deserialize_components(serialized_components)
    end

    # Builds FieldId objects for each covered component.
    #
    # Uses {parsed_items} when available to create {FastIdentifier} objects
    # that bypass Starry re-parsing. Falls back to constructing full
    # {FieldId} objects from the serialized strings.
    #
    # Returns a fresh array each time because some adapter methods may
    # mutate item parameters during field lookup (e.g., deleting "req").
    #
    # @return [Array<FastIdentifier, FieldId>] FieldId objects for each component
    def field_ids
      build_field_ids
    end

    # Returns the signature creation timestamp.
    #
    # @return [Integer, nil] Unix timestamp when the signature was created,
    #   or nil if the `created` parameter is not present
    # @raise [Error] If the `created` parameter exists but is not an integer
    def created
      Integer(parameters["created"])
    rescue
      return nil if parameters["created"].nil?
      raise Error.new "Signature has a non-integer `created` parameter"
    end

    # Checks if the signature is older than a given number of seconds.
    #
    # This is useful for implementing replay attack protection by rejecting
    # signatures that are too old.
    #
    # @param seconds [Integer] The maximum age in seconds
    # @return [Boolean] true if the signature is older than the specified seconds
    # @raise [Error] If the signature is missing the `created` parameter
    #
    # @example Check if signature is older than 5 minutes
    #   signature.older_than?(300)  # => true or false
    def older_than?(seconds)
      raise Error.new "Signature is missing the `created` parameter" if created.nil?
      (Time.now.to_i - created) > seconds
    end

    # Checks if the signature has expired based on the `expires` parameter.
    #
    # If the `expires` parameter is not present, the signature is considered
    # not expired (returns false). If the parameter is present but not a valid
    # integer, an error is raised.
    #
    # @return [Boolean] true if the signature has expired
    # @raise [Error] If the `expires` parameter is not a valid integer
    #
    # @example Check if a signature has expired
    #   signature.expired?  # => true or false
    #
    # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3 RFC 9421 Section 2.3
    def expired?
      return false if !parameters.key?("expires")
      Time.now.to_i >= Integer(parameters["expires"])
    rescue ArgumentError, TypeError
      raise Error.new "Signature has a non-integer `expires` parameter"
    end

    # Converts the signature to HTTP header format.
    #
    # Returns a hash suitable for setting as HTTP headers on a request or
    # response. The hash contains `signature` and `signature-input` keys.
    #
    # @return [Hash{String => String}] Hash with "signature" and "signature-input" keys
    #
    # @example Attaching to a Net::HTTP request
    #   signature.to_h.each { |name, value| request[name] = value }
    def to_h
      return @headers if @headers

      items = @parsed_items || serialized_components.map { |c| Starry.parse_item(c) }
      {
        "signature"       => Starry.serialize({label => value}),
        "signature-input" => Starry.serialize({
          label => Starry::InnerList.new(items, parameters)
        })
      }
    end

    private

    def build_field_ids
      if @parsed_items && @parsed_items.size == @metadata.size
        @metadata.each_with_index.map do |serialized, i|
          item = @parsed_items[i]
          # Clone items that have parameters since the adapter's retrieve
          # method may mutate parameters (e.g., deleting "req").
          unless item.parameters.empty?
            item = Starry::Item.new(item.value, item.parameters.dup)
          end
          Message::Field::FastIdentifier.new(serialized, item)
        end
      else
        @metadata.map { |c| FieldId.new(field_name: c) }
      end
    end

    class << self
      private :new

      # Creates a Signature directly from its constituent parts.
      #
      # This avoids the serialize-then-parse round-trip when the caller
      # (e.g. {Signer.sign}) already has all the data.
      #
      # @api private
      # @param components [Array<String>] Serialized component identifiers
      # @param raw_signature [String] The raw signature bytes
      # @param label [String] The signature label
      # @param parameters [Hash] Signature parameters (symbol keys)
      # @param parsed_items [Array<Starry::Item>] Pre-parsed component items
      # @param headers [Hash] Pre-serialized header strings
      # @return [Signature] The constructed signature
      def from_components(components:, raw_signature:, label:, parameters:, parsed_items:, headers:)
        # Signature stores parameters with string keys (as produced by Starry
        # parsing). Convert symbol keys from Signer to match.
        string_params = {}
        parameters.each { |k, v| string_params[k.to_s] = v }
        new(components, raw_signature, label, string_params,
            parsed_items: parsed_items, headers: headers)
      end

      # Builds a Signature from HTTP headers.
      #
      # Parses the `signature` and `signature-input` headers according to
      # RFC 9421 and RFC 8941 (Structured Field Values).
      #
      # @param headers [Hash{String => String}] HTTP headers containing
      #   `signature` and `signature-input` fields. Keys are case-insensitive.
      # @param options [Hash] Build options
      # @option options [String] :label The signature label to extract when
      #   multiple signatures are present. If not specified and multiple
      #   signatures exist, an error is raised.
      #
      # @return [Signature] The parsed signature
      #
      # @raise [Error] If headers are nil or empty
      # @raise [Error] If required signature headers are missing
      # @raise [Error] If multiple signatures exist and no label is specified
      # @raise [Error] If the specified label is not found
      # @raise [Error] If the headers cannot be parsed as structured fields
      #
      # @example Building from request headers
      #   headers = {
      #     "signature-input" => 'sig1=("@method");created=1618884473',
      #     "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9..=:"
      #   }
      #   signature = Linzer::Signature.build(headers)
      #
      # @example Selecting a specific signature by label
      #   signature = Linzer::Signature.build(headers, label: "sig2")
      def build(headers, options = {})
        basic_validate headers
        headers.transform_keys!(&:downcase)
        validate headers

        input = parse_structured_field(headers, "signature-input")
        reject_multiple_signatures if input.size > 1 && options[:label].nil?
        label = options[:label] || input.keys.first

        signature = parse_structured_field(headers, "signature")
        fail_with_signature_not_found label unless signature.key?(label)

        raw_signature =
          signature[label].value
            .force_encoding(Encoding::ASCII_8BIT)

        fail_due_invalid_components unless input[label].value.respond_to?(:each)

        parsed_items = input[label].value
        components = parsed_items.map { |c| Starry.serialize_item(c) }
        parameters = input[label].parameters

        new(components, raw_signature, label, parameters, parsed_items: parsed_items)
      end

      private

      def basic_validate(headers)
        raise Error.new "Cannot build signature: Request headers cannot be null"      if headers.nil?
        raise Error.new "Cannot build signature: No request headers found"            if headers.empty?
      end

      def validate(headers)
        raise Error.new "Cannot build signature: No \"signature-input\" header found" unless headers.key?("signature-input")
        raise Error.new "Cannot build signature: No \"signature\" header found"       unless headers.key?("signature")
      end

      def reject_multiple_signatures
        raise Error.new "Multiple signatures found but none was selected."
      end

      def fail_with_signature_not_found(label)
        raise Error.new "Signature label not found: \"#{label}\""
      end

      def fail_due_invalid_components
        raise Error.new "Unexpected value for covered components."
      end

      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end

      # Parses a structured field value as a dictionary.
      # @see https://datatracker.ietf.org/doc/html/rfc8941 RFC 8941
      def parse_structured_field(hsh, field_name)
        # Serialized Structured Field values for HTTP are ASCII strings.
        # See: RFC 8941 (https://datatracker.ietf.org/doc/html/rfc8941)
        value = hsh[field_name].encode(Encoding::US_ASCII)
        parse_structured_dictionary(value, field_name)
      end
    end
  end
end
