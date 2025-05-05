# frozen_string_literal: true

RSpec.describe Linzer do
  it "has a version number" do
    expect(Linzer::VERSION).not_to be nil
  end

  context "verifying messages" do
    it "has a ::verify method aliased to Linzer::Verifier::verify" do
      pubkey    = :some_key
      message   = Linzer::Message.new(Linzer.new_request(:get))
      signature = :some_signature

      expect(Linzer::Verifier).to receive(:verify)
        .with(pubkey, message, signature, no_older_than: nil)

      Linzer.verify(pubkey, message, signature)
    end

    context "has a ::verify! method aliased to Linzer::Verifier::verify" do
      it "also wraps the underlying HTTP message and returns true if signature is verifiable" do
        test_private_key = Linzer.generate_ecdsa_p384_sha384_key
        test_pubkey = Linzer.new_ecdsa_p384_sha384_key(test_private_key.material.public_to_pem)

        components = %w[@method @path date x-header]
        headers = {"x-header" => "foo", "date" => Time.now.to_s}
        request = Linzer.new_request(:get, "/baz", {}, headers)

        # let's sign the simulated incoming request first, so we can test verification below
        Linzer.sign!(request, key: test_private_key, components: components)

        expect(Linzer.verify!(request, key: test_pubkey)).to eq(true)
      end

      it "raises an error if underlying HTTP message cannot be verified" do
        test_key = Linzer.generate_ed25519_key
        request = Linzer.new_request(:get, "/foo", {}, {})

        expect { Linzer.verify!(request, key: test_key) }
          .to raise_error(Linzer::Error, /Cannot build signature/)
      end

      it "yields the keyid of the HTTP message signature if a block is passed" do
        response = Linzer::Test::Response.new_response("body", 201, {"header1" => "value1"})
        key = Linzer.generate_ed25519_key
        keyid = "unit-test"
        components = %w[@status header1]

        Linzer.sign!(response,
          key: key,
          components: components,
          params: {
            keyid: keyid
          })

        # the verify! call is expected to fail, we rescue the exception since what's
        # being tested here is that the method will yield the signature keyid to the block
        expect { |b| Linzer.verify!(response, &b) rescue nil }.to yield_with_args(keyid)
      end
    end
  end

  context "signing messages" do
    it "has a ::sign method aliased to Linzer::Signer::sign" do
      key = Linzer.generate_rsa_pss_sha512_key(2048)
      message    = :message
      components = []
      options    = {}

      expect(Linzer::Signer).to receive(:sign)
        .with(key, message, components, options)

      Linzer.sign(key, message, components, options)
    end

    context "has a ::sign! method aliased to Linzer::Signer::sign" do
      it "also mutates the underlying HTTP message to attach a signature" do
        uri = URI("https://example.org/api")
        request = Net::HTTP::Get.new(uri)
        request["foo_header"] = "bar"

        key = Linzer.generate_hmac_sha256_key
        components = %w[foo_header @method @path]

        label   = "sigtest"
        alg     = "hmac-sha256"
        tag     = "unit-test"
        expires = Time.now.to_i + 5000
        Linzer.sign!(request,
          key: key,
          components: components,
          label: label,
          params: {
            alg: alg,
            tag: tag,
            expires: expires
          })

        expect(request["signature"]).to_not       be_empty
        expect(request["signature-input"]).to_not be_empty

        signature_headers = request.each_header.to_h.slice("signature", "signature-input")
        signature = Linzer::Signature.build(signature_headers)

        expect(signature.label).to                 eq(label)
        expect(signature.components).to            eq(components)
        expect(signature.parameters["alg"]).to     eq(alg)
        expect(signature.parameters["tag"]).to     eq(tag)
        expect(signature.parameters["expires"]).to eq(expires)
      end
    end
  end

  it "has a ::new_request method aliased to Linzer::Request::build" do
    uri     = "/some_uri"
    params  = {}
    headers = {"foo" => "bar"}

    expect(Linzer::Request).to receive(:build)
      .with(:get, uri, params, headers)

    Linzer.new_request(:get, uri, params, headers)
  end

  it "has a ::new_response method aliased to Rack::Response::initialize" do
    expect(Rack::Response).to receive(:new)
      .with(:body, :status, {})

    Linzer::Test::Response.new_response(:body, :status, {})
  end
end
