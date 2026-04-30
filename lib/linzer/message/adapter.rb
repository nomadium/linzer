# frozen_string_literal: true

require_relative "adapter/abstract"
require_relative "adapter/generic/request"
require_relative "adapter/generic/response"
require_relative "adapter/net_http/request"
require_relative "adapter/net_http/response"

module Linzer
  class Message
    # Namespace for HTTP message adapters.
    #
    # Adapters provide a unified interface for accessing HTTP message
    # components across different HTTP libraries. Each supported library
    # has its own adapter implementation.
    #
    # @see Abstract Base adapter class
    # @see Rack Rack request/response adapters
    # @see NetHTTP Net::HTTP request/response adapters
    # @see Generic Generic adapters for extension
    module Adapter
    end
  end
end
