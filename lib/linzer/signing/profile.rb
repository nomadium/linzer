# frozen_string_literal: true

module Linzer
  module Signing
    # XXX: add rubydoc?
    module Profile
      # Resolves a signing profile configuration.
      #
      # @param profile [Symbol, Profile::Base, nil]
      # @return [Profile::Base, nil]
      # @raise [Linzer::Error] if the profile is unsupported
      def self.resolve(profile)
        unsupported = "Unknown/unsupported signing profile!"

        case profile
        when NilClass, Profile::Base
          profile
        when Symbol
          case profile
          when :web_bot_auth
            Linzer::Signing::Profile::WebBotAuth.default
          else
            raise Error, unsupported
          end
        else
          raise Error, unsupported
        end
      end

      # Builds a Web Bot Auth signing profile.
      #
      # @param options [Hash]
      # @return [Profile::WebBotAuth]
      def self.web_bot_auth(**options)
        Linzer::Signing::Profile::WebBotAuth.new(**options)
      end

      # Abstract base class for signing profiles.
      #
      # Signing profiles can mutate a signing context before
      # the HTTP Message Signature is generated.
      class Base
        # Applies profile-specific behavior to the signing context.
        #
        # @param ctx [Linzer::Signing::Context]
        # @return [void]
        # @raise [Linzer::Error] when not implemented
        def apply(ctx)
          raise Error, "Sub-classes are required to implement this method!"
        end
      end
    end
  end
end

require_relative "profile/web_bot_auth"
