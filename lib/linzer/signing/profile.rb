# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
      def self.resolve(profile)
        case profile
        when NilClass, Profile::Base
          profile
        when Symbol
          case profile
          when :web_bot_auth
            Linzer::Signing::Profile::WebBotAuth.default
          else
            raise Error, "Unknown/unsupported signing profile!"
          end
        else
          raise Error, "Unknown/unsupported signing profile!"
        end
      end

      def self.web_bot_auth(**options)
        Linzer::Signing::Profile::WebBotAuth(**options)
      end

      class Base
        def apply(ctx)
          raise Error, "Sub-classes must implement this method"
        end
      end
    end
  end
end

require_relative "profile/web_bot_auth"
