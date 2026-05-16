# frozen_string_literal: true

module Linzer
  class Message
    # Overlay is a non-mutating wrapper around a Linzer::Message that provides
    # an additional header layer used during field resolution and signature
    # generation.
    #
    # Resolution precedence:
    #   1. Underlying message (Linzer::Message)
    #   2. Overlay headers
    #
    # Overlay headers are only used when the underlying message does not
    # provide a value for a given header or field.
    # A message wrapper that overlays additional headers onto an existing
    # message without mutating the original message state.
    #
    # Overlay headers participate in component resolution and are attached
    # to the underlying message when signatures are applied.
    #
    # This is primarily used for derived or generated headers that should
    # be visible during signature generation before being persisted onto
    # the underlying HTTP message.
    class Overlay
      # Creates a new overlay message.
      #
      # @param message [Linzer::Message]
      #   The underlying message to wrap
      # @param overlay_headers [#to_h, Hash]
      #   Additional headers to overlay onto the message
      #   A hash-like object containing HTTP headers to use as an overlay layer.
      #   Keys and values must be compatible with Net::HTTP header semantics.
      def initialize(message, overlay_headers)
        @message         = message
        @overlay_headers = overlay_headers

        # Internal adapter-backed overlay used to reuse Linzer's field
        # resolution logic for header/field evaluation.
        @overlay         = build_overlay_message(overlay_headers)
      end

      # Returns an overlaid header value.
      #
      # @param name [String]
      # @return [String, nil]
      def header(name)
        @message.header(name) || @overlay.header(name)
      end

      # Returns true if the field is resolvable from either:
      #   - the underlying message (including derived fields), or
      #   - the overlay adapter (including derived fields)
      #
      # @param field [Linzer::FieldId]
      # @return [Boolean]
      def field?(field)
        @message.field?(field) || @overlay.field?(field)
      end

      # Attaches signature headers to the underlying message together
      # with the overlay headers.
      #
      # Overlay headers are included only at attachment time and do not
      # mutate the underlying message state.
      #
      # @param signature [Linzer::Signature] The signature to attach
      # @return [Object]
      #   The underlying message returned by Linzer::Message#attach!
      def attach!(signature)
        @message.attach!(signature, additional_headers: @overlay_headers.to_h)
      end

      # Retrieves a resolved field value.
      #
      # Values from the underlying message take precedence over overlay
      # header values.
      #
      # @param name [Linzer::FieldId]
      # @return [Object, nil]
      def [](name)
        @message[name] || @overlay[name]
      end

      private

      # Builds a synthetic Net::HTTP request used solely to reuse Linzer's
      # Generic::Request field resolution logic.
      #
      # The URI is a placeholder because only header and field resolution
      # behavior is required; no network request is performed.
      def build_overlay_message(headers)
        request = Net::HTTP::Get.new(URI("https://example.org/"))
        request.initialize_http_header(headers.to_h)
        Adapter::Generic::Request.new(request)
      end
    end
  end
end
