# frozen_string_literal: true

require_relative "profile/base"
require_relative "profile/web_bot_auth"

module Linzer
  class Signature
    # A signing profile defines optional behavior that can modify a signing
    # context prior to HTTP Message Signature generation.
    #
    # Profiles are used to encapsulate domain-specific signing rules such as:
    #
    # - default covered components
    # - parameter enrichment
    # - contextual header injection
    # - policy-based adjustments to signing behavior
    #
    # Profiles are applied *before signature computation* and may mutate
    # {Linzer::Signature::Context}.
    module Profile
      # Resolves a signing profile from a symbolic or object-based reference.
      #
      # This allows callers to pass either:
      #
      # - +nil+ (no profile)
      # - an already constructed profile instance
      # - a symbolic identifier for a registered profile
      #
      # @param profile [Symbol, Profile::Base, nil]
      #   The profile identifier or instance to resolve
      #
      # @return [Profile::Base, nil]
      #   A resolved profile instance, or +nil+ if no profile is used
      #
      # @raise [Linzer::Error]
      #   If the profile symbol is unknown or unsupported
      def self.resolve(profile)
        unsupported = "Unknown/unsupported signing profile!"

        case profile
        when NilClass, Profile::Base
          profile
        when Symbol
          case profile
          when :web_bot_auth
            WebBotAuth.default
          else
            raise Error, unsupported
          end
        else
          raise Error, unsupported
        end
      end

      # Convenience constructor for a Web Bot Auth signing profile.
      #
      # This is a helper for constructing a profile instance directly
      # without using {Profile.resolve}.
      #
      # @param options [Hash]
      #   Options passed through to WebBotAuth initializer
      #
      # @return [Profile::WebBotAuth]
      #   A configured WebBotAuth profile instance
      def self.web_bot_auth(**options)
        WebBotAuth.new(**options)
      end
    end
  end
end
