# frozen_string_literal: true

require_relative "support/test_app"
require_relative "support/test_webserver"

require "linzer/jwa"

RSpec.describe "Signatures verification on responses", :integration do
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

  let(:port) { @web_server.port }
  let(:url)  { "http://localhost:#{port}/" }
  let(:uri)  { URI("http://localhost:#{port}/") }

  let(:verify_key) do
    keys_uri = URI("#{url}.well-known/http-message-signatures-directory")
    response = Net::HTTP.get_response(keys_uri)
    jwk = JWT::JWK.import(JSON.parse(response.body)["keys"][0])
    Linzer::JWA.jwk_import(jwk)
  end

  context "when request is successful" do
    it "verifies the responses are signed by a known key" do
      response = Net::HTTP.get_response(uri)
      headers = response.each_header.to_h
      body = response.body

      expect(response.code.to_i).to             eq(200)
      expect(headers.key?("content-digest")).to eq(true)
      expect(headers["content-digest"]).to      eq(content_digest(body))

      result = Linzer.verify!(response, key: verify_key)
      expect(result).to eq(true)
    end
  end
end
