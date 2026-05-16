# frozen_string_literal: true

module Linzer
  class Message
    # Overlay provides a signing-time augmentation layer for HTTP headers.
    #
    # It allows additional headers to be introduced during HTTP Message
    # Signature generation without mutating the underlying HTTP message.
    #
    # IMPORTANT SEMANTICS
    #
    # Overlay affects ONLY HTTP header resolution.
    #
    # It MUST NOT influence derived HTTP Message Signature components such as:
    #   - @method
    #   - @authority
    #   - @target-uri
    #
    # These values are always computed from the underlying HTTP message.
    #
    # ---
    #
    # Resolution rules:
    #
    # Header lookup:
    #   1. Underlying message headers
    #   2. Overlay headers (fallback only)
    #
    # Derived components:
    #   Always resolved from the underlying message only
    #
    # ---
    #
    # Purpose:
    #
    # This class exists to support signing-time augmentation of header values
    # (e.g., injected or synthesized headers required by signing profiles)
    # without altering the canonical representation of the HTTP message.
    #
    # This is NOT a full message override layer.
    # It is a header-only augmentation mechanism used during signing.
    #
    # DESIGN NOTE:
    # Overlay does not implement full HTTP message semantics.
    # It only participates in header resolution for signing-time evaluation.
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

      # Returns a header value from the signing-time resolution view.
      #
      # Overlay headers are only used if the underlying message does not
      # provide a value for the requested header.
      #
      # Derived components (e.g. @authority, @target-uri) are not affected.
      #
      # @param name [String]
      # @return [String, nil]
      def header(name)
        @message.header(name) || @overlay.header(name)
      end

      # Returns true if the field can be resolved from:
      #
      # - the underlying HTTP message (including derived fields), or
      # - overlay headers (header fields only)
      #
      # NOTE:
      # Overlay headers do not participate in derived component resolution
      # (e.g. @method, @target-uri, @authority).
      #
      # @param field [Linzer::FieldId]
      # @return [Boolean]
      def field?(field)
        @message.field?(field) || (!field.derived? && @overlay.field?(field))
      end

      # Attaches signature headers to the underlying HTTP message.
      #
      # Overlay headers are applied only as HTTP headers at attachment time.
      # They do not affect derived HTTP Message Signature components.
      #
      # @param signature [Linzer::Signature] The signature to attach
      # @return [Object]
      #   The underlying message returned by Linzer::Message#attach!
      def attach!(signature)
        @message.attach!(signature, additional_headers: @overlay_headers.to_h)
      end

      # Retrieves a resolved header or field value from the signing-time view.
      #
      # Resolution order:
      #
      #   1. Underlying HTTP message
      #   2. Overlay headers (fallback only)
      #
      # IMPORTANT:
      # Overlay values are ONLY used when the underlying message does not
      # provide a value. They do not override existing message values.
      #
      # Derived HTTP Message Signature components (e.g. @method,
      # @target-uri, @authority) are always resolved exclusively from the
      # underlying message and are never influenced by overlay headers.
      #
      # @param name [Linzer::FieldId]
      # @return [Object, nil]
      def [](name)
        value = @message[name]
        return value unless value.nil?

        @overlay[name]
      end

      private

      # Builds a synthetic Net::HTTP request used solely to reuse Linzer's
      # Generic::Request field resolution logic.
      #
      # The URI is a placeholder because only header and field resolution
      # behavior is required; no network request is performed.
      def build_overlay_message(headers)
        request = Net::HTTP::Get.new(URI("https://example.invalid/"))
        request.initialize_http_header(headers.to_h)
        Adapter::Generic::Request.new(request)
      end
    end
  end
end
