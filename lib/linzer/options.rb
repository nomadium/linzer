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

    def self.prepare_web_bot_auth!(message, args, components, options)
      key = args[:key]
      raise Error, "Unsupported/invalid key!" unless key.is_a?(Linzer::JWS::Key)

      # user just want options following IETF draft guidelines for web bot auth,
      # unless the user override them
      #
      if args[:web_bot_auth] == true
        set_web_bot_auth_options!(key, components, options)
        return
      end

      # user needs additional control by passing a hash
      # if that's not the case, then this is an error
      #
      if !args[:web_bot_auth].responds_to?(:to_h)
        raise Error, "Invalid value for web_both_auth options!"
      end

      agent = args[:web_bot_auth][:agent]
      set_web_auth_agent!(agent, options[:label], message, components) if agent

      set_web_auth_options!(key, components, options) if args[:web_bot_auth][:params] == :recommended
      options[:nonce] = generate_web_bot_auth_nonce   if args[:web_bot_auth][:nonce]  == :generate
    end

    def self.set_web_bot_auth_options!(key, components, options)
      if (components & ["@authority", "@request-uri"]).empty?
        components << %w[@authority @request-uri].sample
      end

      options[:expires] = Time.now.to_i + 3600        unless options[:expires]
      options[:tag]     = "web-bot-auth"              unless options[:tag]
      options[:keyid]   = key.material.key_digest     unless options[:keyid]
      options[:nonce]   = generate_web_bot_auth_nonce unless options[:nonce]
    end

    def self.set_web_auth_agent!(agent, label, message, components)
      if !message["signature-agent"] || message["signature-agent"] != agent
        message.set_header!("signature-agent", Starry.serialize_dictionary(label => agent))
        components << "signature-agent;key=\"#{label}\""
      end
    end

    def self.generate_web_bot_auth_nonce
      SecureRandom.urlsafe_base64(64)
    end
  end
end
