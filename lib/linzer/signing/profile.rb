# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
      def self.resolve(profile)
        case profile
        when NilClass, Profile::Base
          return profile
        when Symbol
          case profile
          when :web_bot_auth
            return Linzer::Signing::Profile::WebBotAuth.default
          else
            raise Error, "Unknown/unsupported signing profile!"
          end
        else
          raise Error, "Unknown/unsupported signing profile!"
        end
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
