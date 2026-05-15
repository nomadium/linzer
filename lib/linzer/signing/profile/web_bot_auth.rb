# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
      class WebBotAuth < Base
        def initialize(params: :recommended, nonce: :generate, agent: nil)
          @params = params
          @nonce  = nonce
          @agent  = agent
        end

        def apply(ctx)
          validate ctx

          if @params == :recommended
            set_web_bot_auth_options!(ctx.key, ctx.components, ctx.params)
          end

          if @nonce == :generate
            ctx.params[:nonce] = generate_web_bot_auth_nonce
          end

          if @agent
            set_web_auth_agent!(@agent, ctx.params[:label], ctx.message, ctx.components)
          end
        end

        def self.default
          new(params: :recommended, nonce: :generate)
        end

        private

        # Applies the recommended Web Bot Auth signature parameters.
        #
        # This method ensures that the covered components and signature
        # parameters comply with the Web Bot Auth recommendations.
        #
        # @param key [Linzer::JWS::Key] signing key
        # @param components [Array<String>] covered signature components
        # @param options [Hash] signature parameters/options to mutate
        # @return [void]
        def set_web_bot_auth_options!(key, components, options)
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
          options[:expires] = Time.now.to_i + 3600     unless options[:expires]
          options[:tag]     = "web-bot-auth"           unless options[:tag]
          options[:keyid]   = key.material.key_digest  unless options[:keyid]
        end

        # Sets the Signature-Agent header and adds it to the covered components.
        #
        # @param agent [String] agent identifier URI
        # @param label [String] signature label
        # @param message [Linzer::Message] message being signed
        # @param components [Array<String>] covered signature components
        # @return [void]
        # @raise [Linzer::Error] if the header value cannot be serialized
        def set_web_auth_agent!(agent, label, message, components)
          if !message["signature-agent"] || message["signature-agent"] != agent
            message["signature-agent"] = Starry.serialize_dictionary(label => agent)
            components << "\"signature-agent\";key=\"#{label}\""
          end
        rescue Starry::SerializeError => ex
          raise Error,
                "Invalid signature-agent header value!",
                cause: ex
        end

        def validate(ctx)
          raise Error, "Unsupported/invalid key!" unless ctx.key.is_a?(Linzer::JWS::Key)
          raise Error, "Web Bot Auth is defined only for requests!" unless ctx.message.request?
        end

        # Generates a nonce suitable for Web Bot Auth signatures.
        #
        # @return [String] a URL-safe random nonce
        def generate_web_bot_auth_nonce
          SecureRandom.urlsafe_base64(64)
        end
      end
    end
  end
end
