# frozen_string_literal: true

# XXX: This could be a struct
module Linzer
  # XXX: Maybe move to under Signature instead?
  module Signing
    # Encapsulates mutable signing state used by signing profiles.
    #
    # A signing context contains the message being signed together with
    # the signing key, covered components, and signature parameters.
    # Profiles may mutate the context before signature generation.
    #
    # @attr_reader [Linzer::Message] message
    #   the HTTP message being signed
    #
    # @attr_reader [Object] key
    #   the signing key used to generate the signature
    #
    # @attr_reader [Array<String>] components
    #   covered signature components
    #
    # @attr_reader [Hash] params
    #   signature parameters
    #
    # @attr_reader [Hash] extra_headers
    #   XXX: TO-DO
    class Context
      # Creates a new signing context.
      #
      # @param message [Linzer::Message]
      # @param key [Linzer::Key]
      # @param label [String, nil]
      # @param components [Array<String>]
      # @param params [Hash]
      def initialize(message:, key:, label:, components:, params:)
        @message       = message
        @key           = key
        @components    = components.dup
        # XXX: maybe dup is not needed in the merge case?
        @params        = label ? params.dup.merge(label: label) : params.dup
        @extra_headers = {}
      end
      attr_reader :key, :components, :params, :extra_headers

      # XXX: TO-DO: missing rubydoc
      def message
        return @overlay_message  if @overlay_message
        return @message          if @extra_headers.empty?

        # XXX: extra_headers or virtual_headers?
        @overlay_message = @message.with_headers(extra_headers)
      end
    end
  end
end
