# frozen_string_literal: true

module Linzer
  # Default configuration options for HTTP message signatures.
  #
  # These defaults provide a reasonable starting point for most applications.
  # They can be overridden when signing or in middleware configuration.
  module Options
    # Default configuration values.
    #
    # @return [Hash] Frozen hash of default options
    #
    # @option DEFAULT [Array<String>] :covered_components Default components
    #   to include in signatures: `@method`, `@request-target`, `@authority`,
    #   and `date`. These provide good baseline security for most use cases.
    #
    # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.1 RFC 9421 Section 7.2.1
    DEFAULT = {
      covered_components: %w[@method @request-target @authority date]
    }.freeze

    # Applies Web Bot Auth configuration to signing options and covered
    # components.
    #
    # This helper validates the provided key and request type, then applies
    # Web Bot Auth defaults and optional configuration described by the
    # current IETF drafts.
    #
    # @param message [Linzer::Message] the message being signed
    # @param args [Hash] signing arguments
    # @param components [Array<String>] covered signature components
    # @param options [Hash] signature parameters/options to mutate
    # @return [void]
    # @raise [Linzer::Error] if the configuration is invalid
    def self.prepare_web_bot_auth!(message, args, components, options)
      key = args[:key]
      raise Error, "Unsupported/invalid key!" unless key.is_a?(Linzer::JWS::Key)
      raise Error, "Web Bot Auth is defined only for requests!" unless message.request?

      # user just want options following IETF draft guidelines for Web Bot Auth
      #
      if args[:web_bot_auth] == true
        set_web_bot_auth_options!(key, components, options)
        options[:nonce] = generate_web_bot_auth_nonce unless options[:nonce]
        return
      end

      # user needs additional control by passing a hash
      #
      if !args[:web_bot_auth].respond_to?(:to_h)
        raise Error, "Unsupported value for web_both_auth configuration"
      end

      settings = args[:web_bot_auth]
      agent    = settings[:agent]
      set_web_auth_agent!(agent, options[:label], message, components) if agent

      if (!settings[:nonce] && !options[:nonce]) || settings[:nonce] == :generate
        options[:nonce] = generate_web_bot_auth_nonce
      end

      if !settings[:params] || settings[:params] == :recommended
        set_web_bot_auth_options!(key, components, options)
      end
    end

    # Applies the recommended Web Bot Auth signature parameters.
    #
    # This method ensures that the covered components and signature
    # parameters comply with the Web Bot Auth recommendations.
    #
    # @param key [Linzer::JWS::Key] signing key
    # @param components [Array<String>] covered signature components
    # @param options [Hash] signature parameters/options to mutate
    # @return [void]
    def self.set_web_bot_auth_options!(key, components, options)
      # 4.2. Generating HTTP Message Signature
      #
      # Agents MUST include at least one of the following components:
      # - @authority
      # - @target-uri
      #
      if (components & ["@authority", "@target-uri"]).empty?
        components << %w[@authority @target-uri].sample
      end

      # Agents MUST include the following @signature-params:
      # - created
      # - expires
      # - keyid MUST be a base64url JWK SHA-256 Thumbprint
      # - tag MUST be web-bot-auth
      #
      # options[:created] is set by default by linzer at signature creation time
      #
      options[:expires] = Time.now.to_i + 3600    unless options[:expires]
      options[:tag]     = "web-bot-auth"          unless options[:tag]
      options[:keyid]   = key.material.key_digest unless options[:keyid]
    end

    # Sets the Signature-Agent header and adds it to the covered components.
    #
    # @param agent [String] agent identifier URI
    # @param label [String] signature label
    # @param message [Linzer::Message] message being signed
    # @param components [Array<String>] covered signature components
    # @return [void]
    # @raise [Linzer::Error] if the header value cannot be serialized
    def self.set_web_auth_agent!(agent, label, message, components)
      if !message["signature-agent"] || message["signature-agent"] != agent
        message["signature-agent"] = Starry.serialize_dictionary(label => agent)
        components << "\"signature-agent\";key=\"#{label}\""
      end
    rescue Starry::SerializeError => ex
      raise Error, "Invalid signature-agent header value!", cause: ex
    end

    # Generates a nonce suitable for Web Bot Auth signatures.
    #
    # @return [String] a URL-safe random nonce
    def self.generate_web_bot_auth_nonce
      SecureRandom.urlsafe_base64(64)
    end
  end
end
