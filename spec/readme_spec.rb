# frozen_string_literal: true

def build_random_signature(label)
  Starry.serialize_dictionary({label => SecureRandom.random_bytes(64)})
end

RSpec.describe "README usage" do
  let(:key) { Linzer.generate_ed25519_key }

  let(:pubkey) do
    exported_pubkey = key.material.public_to_pem
    Linzer.new_ed25519_public_key(exported_pubkey, "some-key-ed25519")
  end

  describe "HTTP request examples" do
    let(:headers) do
      {
        "date" => "Fri, 23 Feb 2024 17:57:23 GMT",
        "x-custom-header" => "foo"
      }
    end

    let(:request) { Linzer.new_request(:post, "/some_uri", {}, headers) }

    let(:message) { Linzer::Message.new(request) }

    let(:fields)  { %w[date x-custom-header @method @path] }

    let(:signature) { Linzer.sign(key, message, fields) }

    it "signs an HTTP request message" do
      expect(message.request?).to       eq(true)
      expect(signature.components).to   eq(fields)
      expect(signature.value.length).to eq(64)
    end

    it "verifies a valid signature" do
      signed_headers   = headers.merge(signature.to_h)
      valid_signature  = Linzer::Signature.build(signed_headers)

      expect(Linzer.verify(pubkey, message, valid_signature)).to eq(true)
    end

    it "cannot verify an invalid signature" do
      random_signature = build_random_signature("sig1")
      signed_headers   = signature.to_h.merge({"signature" => random_signature})
      bad_signature    = Linzer::Signature.build(signed_headers)

      expect { Linzer.verify(pubkey, message, bad_signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end
  end

  describe "HTTP response examples" do
    let(:headers) do
      {
        "date"              => "Sat, 30 Mar 2024 21:40:13 GMT",
        "x-response-custom" => "bar"
      }
    end

    let(:response) { Linzer.new_response("request body", 200, headers) }

    let(:message) { Linzer::Message.new(response) }

    let(:fields)  { %w[@status date x-response-custom] }

    let(:signature) { Linzer.sign(key, message, fields) }

    it "signs an HTTP response message" do
      expect(message.response?).to      eq(true)
      expect(signature.components).to   eq(fields)
      expect(signature.value.length).to eq(64)
    end

    it "verifies a valid signature" do
      signed_headers   = headers.merge(signature.to_h)
      valid_signature  = Linzer::Signature.build(signed_headers)

      expect(Linzer.verify(pubkey, message, valid_signature)).to eq(true)
    end

    it "cannot verify an invalid signature" do
      random_signature = build_random_signature("sig1")
      signed_headers   = signature.to_h.merge({"signature" => random_signature})
      bad_signature    = Linzer::Signature.build(signed_headers)

      expect { Linzer.verify(pubkey, message, bad_signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end
  end
end
