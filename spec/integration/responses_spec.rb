# frozen_string_literal: true

require_relative "support/test_app"
require_relative "support/test_webserver"

$MYMESSAGE = nil
$MYSIGNATURE = nil
# algo.verify(data: $MYMESSAGE, signature: signature, verification_key: one_key)

require "jwt"
require "jwt/eddsa"
require "linzer/jwa"

if true
  module JWT
    class EncodedToken
      def valid_signature?(algorithm:, key:)
        Array(JWA.resolve_and_sort(algorithms: algorithm, preferred_algorithm: header['alg'])).any? do |algo|
          Array(key).any? do |one_key|
            binding.irb
            algo.verify(data: signing_input, signature: signature, verification_key: one_key)
          end
        end
      end
    end
  end
end

if false
module JWT
  class Token
    def sign!(algorithm:, key:)
      binding.irb
      raise ::JWT::EncodeError, 'Token already signed' if @signature
      binding.irb

      JWA.resolve(algorithm).tap do |algo|
        binding.irb
        header.merge!(algo.header)
        binding.irb
        @signature = algo.sign(data: signing_input, signing_key: key)
      end

      binding.irb
      nil
    end
  end
end
end

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

    def foobar(response)
      jwk = JWT::JWK.import(JSON.load(response.body)["keys"][0])
      other_response = Net::HTTP.get_response(uri)
      public_key = Linzer::JWA.jwk_import(jwk)
      binding.irb
      result = Linzer.verify!(other_response, key: public_key, no_older_than: 600)
      expect(result).to eq(true)
      binding.irb
      message = Linzer::Message.new(other_response)
      signature = Linzer::Signature.build(other_response.each_header.to_h)
      puts jwk.verify_key.verify(signature.value, Linzer::Common.signature_base(message, signature.components, signature.parameters))

      fields = ["{\"alg\":\"EdDSA\"}", Linzer::Common.signature_base(message, signature.components, signature.parameters).inspect, signature.value]

      $MYMESSAGE = Linzer::Common.signature_base(message, signature.components, signature.parameters)
      $MYSIGNATURE = signature.value

      token = fields.map { |f| Base64.urlsafe_encode64(f, padding:false) }.join(".")

      # algo = JWT::JWA.resolve("EdDSA")
      # mytoken = JWT::Token.new(payload: Linzer::Common.signature_base(message, signature.components, signature.parameters))
      # mytoken.instance_variable_set(:@signature, signature.value)
      # binding.irb

      private_key = Ed25519::SigningKey.generate
      msg = Linzer::Common.signature_base(message, signature.components, signature.parameters)
      token2 = JWT.encode(msg, private_key, "EdDSA")
      # payload, header = JWT.decode(token, private_key.verify_key, true, algorithm: "EdDSA")

      # binding.irb
      verify_key = jwk.verify_key
      verify_signature = true
      opts = {algorithm: "EdDSA"}
      # binding.irb
      payload, header = JWT.decode(token, verify_key, verify_signature, **opts)
      # payload, header = JWT.decode(mytoken.jwt, verify_key, verify_signature, **opts)
    end

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
        foobar(keys_response)
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
