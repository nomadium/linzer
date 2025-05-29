# frozen_string_literal: true

require_relative "support/test_app"
require_relative "support/test_webserver"

RSpec.describe "Test signed responses from a local web server", :integration do
  let(:debug) { false }

  before(:all) do
    app = Linzer::Test::TestApp.new
    @web_server = Linzer::Test::TestWebServer.new(app)
    @web_server.wait_until_responsive(timeout: 5)
  end

  after(:all) do
    @web_server.kill
  end

  def content_digest(data)
    Starry.serialize("sha-256" => Digest::SHA256.digest(data))
  end

  context "foo" do
    let(:port) { @web_server.port }
    let(:url)  { "http://localhost:#{port}/" }
    let(:uri)  { URI("http://localhost:#{port}/") }

    context "when request is successful" do
      it "verifies the responses are signed by a known key" do
        puts uri
        response = Net::HTTP.get_response(uri)
        headers = response.each_header.to_h
        body = response.body

        expect(response.code).to eq("200")
        expect(headers.key?("content-digest")).to eq(true)
        expect(headers["content-digest"]).to eq(content_digest(body))
        puts response.body
        puts response.each_header.to_h
        puts "#" * 50
        puts "#" * 50

        keys_uri = URI("#{url}.well-known/http-message-signatures-directory")
        keys_response = Net::HTTP.get_response(keys_uri)
        keys_headers = keys_response.each_header.to_h

        expect(keys_headers.key?("content-digest")).to eq(true)
        expect(keys_headers["content-digest"])
          .to eq(content_digest(keys_response.body))

        keys_data = JSON.parse(keys_response.body)
        keys_data["keys"].first

        pubkey_uri = URI("#{url}/pubkey")
        pubkey_response = Net::HTTP.get_response(pubkey_uri)
        pubkey_pem = pubkey_response.body
        @pubkey = Linzer.new_ed25519_key(pubkey_pem)

        expect(Linzer.verify!(pubkey_response, key: @pubkey)).to eq(true)
        expect(Linzer.verify!(keys_response, key: @pubkey)).to eq(true)
        expect(Linzer.verify!(response, key: @pubkey)).to eq(true)

        #         # expect(response.body).to eq("Hello world sinatra!")
        #         expect(response.each_header.to_h.key?("signature")).to eq(true)
        #         expect(response.each_header.to_h.key?("content-digest")).to eq(true)
        #         uri2 = URI("#{url}.well-known/http-message-signatures-directory")
        #         response2 = Net::HTTP.get_response(uri2)
        #         puts response2.each_header.to_h
        #         puts response2.body
      end
    end
  end
end
