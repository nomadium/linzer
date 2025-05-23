# frozen_string_literal: true

require "webrick"
require "rackup/handler/webrick"
require_relative "support/test_app"

RSpec.describe "Test signed responses from a local web server", :integration do
  let(:debug) { false }

  before(:all) do
    @port = 9293
    @server_thread = Thread.new do
      server_opts = {
        Port: @port,
        AccessLog: [],
        Logger: WEBrick::Log.new(File::NULL)
      }
      # binding.irb
      Rackup::Handler::WEBrick.run(Linzer::Test::TestApp.new, **server_opts)
    end
    wait_until_responsive("http://localhost:#{@port}/", timeout: 5)
  end

  after(:all) do
    Thread.kill(@server_thread)
  end

  def wait_until_responsive(url, timeout: 5)
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

  context "foo" do
    context "bar" do
      it "baz" do
        uri = URI("http://localhost:#{@port}/")
        response = Net::HTTP.get_response(uri)

        expect(response.code).to eq("200")
        # expect(response.body).to eq("Hello world sinatra!")
        expect(response.each_header.to_h.key?("signature")).to eq(true)
      end
    end
  end
end
