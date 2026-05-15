# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
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

      def self.web_bot_auth(**options)
        Linzer::Signing::Profile::WebBotAuth(**options)
      end

      class Base
        def apply(ctx)
          raise Error, "Sub-classes are required to implement this method!"
        end
      end
    end
  end
end

require_relative "profile/web_bot_auth"
