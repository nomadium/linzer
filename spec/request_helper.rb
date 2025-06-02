# frozen_string_literal: true

module Linzer
  module Test
    module RequestHelper
      extend self

      def example_proxy_request
        uri = URI("http://origin.host.internal.example/foo?param=Value&Pet=dog")
        headers = {
          "date"           => "Tue, 20 Apr 2021 02:07:56 GMT",
          "forwarded"      => "for=192.0.2.123;host=example.com;proto=https",
          "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
          "content-length" => "18"
        }
        request = Net::HTTP::Post.new(uri, headers)
        request.content_type = "application/json"
        request.body = '{"hello": "world"}'
        request
      end
    end
  end
end
