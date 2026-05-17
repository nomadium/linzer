# frozen_string_literal: true

module Linzer
  class Signature
    # A mutable context object used during signature generation.
    #
    # The context represents all state required to produce a signature,
    # including:
    #
    # - the HTTP message being signed
    # - the signing key
    # - covered signature components
    # - signature parameters
    # - optional overlay headers introduced by signing profiles
    #
    # Profiles may mutate this context before or during signing in order
    # to influence the final signature output (e.g., adding headers,
    # modifying components, or adjusting parameters).
    #
    # This object is intentionally mutable and is not thread-safe.
    #
    # @attr_reader [Linzer::Message] message
    #   the HTTP message being signed
    #
    # @attr_reader [Object] key
    #   the signing key used to generate the signature
    #
    # @attr_reader [Array<String>] components
    #   list of covered signature components
    #
    # @attr_reader [Hash] params
    #   signature parameters (may include :label if provided)
    #
    # @attr_reader [Hash] overlay_headers
    #   Overlay headers are merged into the message view during signature
    #   computation but do not mutate the underlying message.
    class Context
      # Creates a new signing context.
      #
      # @param message [Linzer::Message]
      #   The HTTP message being signed
      #
      # @param key [Linzer::Key]
      #   The signing key used to generate the signature
      #
      # @param label [String, nil]
      #   Optional signature label. If provided, it is merged into params
      #   as `:label`.
      #
      # @param components [Array<String>]
      #   The list of HTTP components covered by the signature
      #
      # @param params [Hash]
      #   Signature parameters passed to the signing algorithm
      def initialize(message:, key:, label:, components:, params:)
        @message         = message
        @key             = key
        @components      = components.dup
        @params          = (label ? params.merge(label: label) : params).dup
        @overlay_headers = {}
      end
      attr_reader :key, :components, :params, :overlay_headers

      # Returns a message view that includes any overlay headers.
      #
      # The returned object is cached after first construction.
      #
      # Overlay headers are applied lazily and only affect the derived
      # signing view; the original message remains unchanged.
      #
      # @return [Linzer::Message]
      def message
        return @overlay_message  if defined?(@overlay_message)
        return @message          if @overlay_headers.empty?

        @overlay_message = @message.with_headers(overlay_headers)
      end
    end
  end
end
