# frozen_string_literal: true

require "socket"
require "webrick"
require "rackup/handler/webrick"
require "net/http"

module Linzer
  module Test
    class TestWebServer
      def initialize(rack_app)
        @port = find_free_port
        @server_thread = Thread.new do
          server_opts = {
            Port: @port,
            AccessLog: [],
            Logger: WEBrick::Log.new(File::NULL)
          }
          Rackup::Handler::WEBrick.run(rack_app, **server_opts)
        end
      end

      attr_reader :port

      def wait_until_responsive(url = "http://localhost:#{@port}/", timeout: 5)
        deadline = Time.now + timeout
        until Time.now > deadline
          begin
            response = Net::HTTP.get_response(URI(url))
            return if response.is_a?(Net::HTTPSuccess)
          rescue Errno::ECONNREFUSED, SocketError
            sleep 0.1
          end
        end
        raise "Server at #{url} did not start in time"
      end

      def kill
        @server_thread.kill
      end

      private

      def find_free_port
        max_attempts = 100
        count = 0
        loop do
          some_port = rand(1024..65535)
          return some_port if port_available?(some_port)
          count += 1
          raise "Unable to find an available port" if count >= max_attempts
        end
      end

      def port_available?(some_port)
        socket = TCPServer.new("::1", some_port)
        socket.close
        socket.closed?
      rescue Errno::EADDRINUSE, Errno::EACCES
        false
      end
    end
  end
end
