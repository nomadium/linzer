# frozen_string_literal: true

module Linzer
  module Response
    def new_response(body = nil, status = 200, headers = {})
      Rack::Response.new(body, status, headers.transform_values(&:to_s))
    end
  end
end
