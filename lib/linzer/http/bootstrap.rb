# frozen_string_literal: true

module Linzer
  module HTTP
    # Handles lazy loading of http.rb gem dependencies.
    #
    # The http.rb gem integration is optional and only loaded when
    # explicitly required via `require "linzer/http/signature_feature"`.
    #
    # @api private
    module Bootstrap
      class << self
        # Requires the http gem and related adapters.
        # @api private
        def require_dependencies
          require "http"
          require_relative "../message/adapter/http_gem/request"
        end

        # Loads dependencies, raising a helpful error if http gem is missing.
        # @raise [Error] If the http gem is not installed
        # @api private
        def load_dependencies
          require_dependencies
        rescue LoadError
          msg = "http gem is required to be installed to use this feature."
          raise Linzer::Error, msg
        end
      end
    end
  end
end
