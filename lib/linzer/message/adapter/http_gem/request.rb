# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      # http.rb gem message adapters.
      #
      # Provides adapters for {HTTP::Request} and {HTTP::Response} objects
      # from the http.rb gem.
      #
      # @note These adapters are loaded on-demand when using the
      #   {Linzer::HTTP::SignatureFeature}.
      module HTTPGem
        # Adapter for {HTTP::Request} objects from http.rb gem.
        #
        # Extends the generic request adapter with http.rb-specific
        # method name retrieval.
        class Request < Generic::Request
          private

          def derived(name)
            return @operation.uri.host         if name.value == "@authority"
            return @operation.verb.to_s.upcase if name.value == "@method"
            super
          end
        end
      end
    end
  end
end
