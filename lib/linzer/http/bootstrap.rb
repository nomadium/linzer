# frozen_string_literal: true

module Linzer
  module HTTP
    module Bootstrap
      class << self
        def require_dependencies
          require "http"
          require_relative "../message/adapter/http_gem/request"
        end

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
