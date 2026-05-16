# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
      # Web Bot Auth signing profile implementation.
      #
      # This profile applies the behavior defined in the Web Bot Auth
      # HTTP Message Signatures draft specification.
      #
      # It mutates a signing context to ensure compliance with the
      # spec requirements, including:
      #
      # - selection of required signature components
      # - generation of nonce values
      # - enforcement of Web Bot Auth signature parameters
      # - optional Signature-Agent header injection
      #
      # ## Lifecycle
      #
      # 1. Context is created
      # 2. Profile is resolved
      # 3. {#apply} mutates signing context
      # 4. signature is generated using modified context
      #
      # @see https://datatracker.ietf.org/wg/webbotauth/documents/
      class WebBotAuth < Base
        # Creates a new Web Bot Auth signing profile.
        #
        # @param params [Symbol, nil]
        #   Controls default Web Bot Auth signature parameters.
        #
        #   - :recommended → apply Web Bot Auth recommended defaults
        #   - nil → do not modify signature parameters
        #
        # @param nonce [Symbol, nil]
        #   Controls nonce generation behavior.
        #
        #   - :generate → inject a cryptographically random nonce
        #   - nil → no nonce is added
        #
        # @param agent [String, nil]
        #   Optional Signature-Agent identifier URI.
        #
        #   When provided, a structured Signature-Agent header is injected
        #   and included as a covered signature component.
        def initialize(params: :recommended, nonce: :generate, agent: nil)
          @params = params
          @nonce  = nonce
          @agent  = agent
        end

        SIGNATURE_AGENT = "signature-agent"
        private_constant :SIGNATURE_AGENT

        REQUIRED_AUTH_COMPONENTS = %w[@authority @target-uri].freeze

        # Applies the Web Bot Auth profile to a signing context.
        #
        # This method mutates:
        # - signature parameters (ctx.params)
        # - covered components (ctx.components)
        # - overlay headers (ctx.overlay_headers)
        #
        # @param ctx [Linzer::Signing::Context]
        #   Mutable signing context
        #
        # @return [void]
        # @raise [Linzer::Error]
        #   If key or message are incompatible with Web Bot Auth rules
        def apply(ctx)
          validate ctx.key, ctx.message

          if @params == :recommended
            set_params!(ctx.key, ctx.components, ctx.params)
          end

          ctx.params[:nonce] = generate_nonce if @nonce == :generate

          if @agent
            set_agent!(
              @agent,
              ctx.params[:label],
              ctx.message,
              ctx.components,
              ctx.overlay_headers
            )
          end
        end

        # Returns a default Web Bot Auth profile instance.
        #
        # This represents the standard recommended configuration:
        #
        # - recommended signature parameters enabled
        # - nonce generation enabled
        #
        # @return [WebBotAuth]
        def self.default
          new(params: :recommended, nonce: :generate)
        end

        private

        # Applies Web Bot Auth recommended signature parameter rules.
        #
        # This ensures compliance with Web Bot Auth requirements:
        #
        # - At least one of @authority or @target-uri must be covered
        # - expires is set to a default lifetime if not provided
        # - tag is set to "web-bot-auth"
        # - keyid is derived from the signing key fingerprint
        #
        # @param key [Linzer::JWS::Key]
        # @param components [Array<String>]
        # @param params [Hash]
        # @return [void]
        def set_params!(key, components, params)
          # 4.2. Generating HTTP Message Signature
          #
          # Agents MUST include at least one of the following components:
          # - @authority
          # - @target-uri
          #
          if (components & REQUIRED_AUTH_COMPONENTS).empty?
            components << REQUIRED_AUTH_COMPONENTS.sample
          end

          # Agents MUST include the following @signature-params:
          # - created
          # - expires
          # - keyid MUST be a base64url JWK SHA-256 Thumbprint
          # - tag MUST be web-bot-auth
          #
          # options[:created] is set by default by linzer at signature creation time
          #
          params[:expires] ||= Time.now.to_i + 3600
          params[:tag]     ||= "web-bot-auth"
          params[:keyid]   ||= key.material.key_digest
        end

        # Injects and signs the Signature-Agent header.
        #
        # The header is only added if:
        # - it is not already present, OR
        # - its value differs from the configured agent
        #
        # When added:
        # - a structured Signature-Agent header is written into overlay headers
        # - the corresponding structured field is added to covered components
        #
        # @param agent [String]
        # @param label [String]
        # @param message [Linzer::Message]
        # @param components [Array<String>]
        # @param overlay_headers [Hash]
        # @return [void]
        # @raise [Linzer::Error]
        #   If the header cannot be serialized as a structured field
        def set_agent!(agent, label, message, components, overlay_headers)
          if message[SIGNATURE_AGENT] != agent
            overlay_headers["signature-agent"] =
              Starry.serialize_dictionary(label => agent)

            item = Starry::Item.new(SIGNATURE_AGENT, key: label)
            serialized_item = Starry.serialize(item)
            if !components.include?(serialized_item)
              components << serialized_item
            end
          end
        rescue Starry::SerializeError => ex
          raise Error,
                "Invalid #{SIGNATURE_AGENT} header value!",
                cause: ex
        end

        # Validates that the context is compatible with Web Bot Auth.
        #
        # @param key [Object]
        # @param message [Linzer::Message]
        # @return [void]
        # @raise [Linzer::Error]
        def validate(key, message)
          raise Error, "Unsupported/invalid key!" unless key.is_a?(Linzer::JWS::Key)
          raise Error, "Web Bot Auth is defined only for requests!" unless message.request?
        end

        # Generates a cryptographically random nonce.
        #
        # The nonce is URL-safe and suitable for inclusion in HTTP signature
        # parameters.
        #
        # @return [String]
        def generate_nonce
          SecureRandom.urlsafe_base64(64)
        end
      end
    end
  end
end
