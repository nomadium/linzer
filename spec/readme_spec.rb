# frozen_string_literal: true

require "digest"
require "time"

def build_random_signature(label)
  Linzer::HTTP::StructuredField.serialize_dictionary({label => SecureRandom.random_bytes(64)})
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

    let(:request) { Linzer::Test::RackHelper.new_request(:post, "/some_uri", {}, headers) }

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

    it "allows validating the `created` parameter" do
      signed_headers   = headers.merge(signature.to_h)
      valid_signature  = Linzer::Signature.build(signed_headers)
      p valid_signature.parameters

      expect(Linzer.verify(pubkey, message, valid_signature, no_older_than: 300)).to eq(true)
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

    let(:response) { Linzer::Test::RackHelper.new_response("request body", 200, headers) }

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

  describe "Covering the message content (Content-Digest) example" do
    def content_digest(body)
      Linzer::HTTP::StructuredField
        .serialize_dictionary("sha-256" => Digest::SHA256.digest(body))
    end

    def content_digest_valid?(header, body)
      digests  = Linzer::HTTP::StructuredField.parse_dictionary(header)
      expected = digests["sha-256"]&.value or return false
      expected == Digest::SHA256.digest(body)
    rescue Linzer::Error
      false
    end

    let(:body)       { '{"status": "open"}' }
    let(:components) { %w[@method @request-target @authority date content-type content-digest] }

    let(:request) do
      # QUERY is only available with net-http >= 0.10.0
      request_class = defined?(Net::HTTP::Query) ? Net::HTTP::Query : Net::HTTP::Post
      request_class.new(URI("https://example.org/api/tasks")).tap do |req|
        req.body              = body
        req["date"]           = Time.now.httpdate
        req["content-type"]   = "application/json"
        req["content-digest"] = content_digest(body)
      end
    end

    let(:signature) do
      Linzer.sign!(request, key: key, components: components)
      Linzer::Signature.build(request.each_header.to_h)
    end

    it "computes the Content-Digest value shown in the README" do
      expect(content_digest(body))
        .to eq("sha-256=:0Q+mqIIRDMBY3TV4HoaYEcXRNgBG4Mrv5OG0/GtJ+N8=:")
    end

    it "verifies the signature and the content digest of an untouched request" do
      expect(Linzer.verify(pubkey, Linzer::Message.new(request), signature)).to eq(true)
      expect(content_digest_valid?(request["content-digest"], request.body)).to eq(true)
    end

    it "detects a modified body only by checking the content digest" do
      signature
      request.body = '{"status": "closed"}'

      expect(Linzer.verify(pubkey, Linzer::Message.new(request), signature)).to eq(true)
      expect(content_digest_valid?(request["content-digest"], request.body)).to eq(false)
    end

    it "rejects the signature if the content digest is replaced" do
      signature
      request.body              = '{"status": "closed"}'
      request["content-digest"] = content_digest(request.body)

      expect { Linzer.verify(pubkey, Linzer::Message.new(request), signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    it "rejects malformed or mismatched Content-Digest headers" do
      expect(content_digest_valid?("not a dictionary", body)).to eq(false)
      expect(content_digest_valid?("sha-512=:AAAA:", body)).to eq(false)
      expect(content_digest_valid?("sha-256=:AAAA:", body)).to eq(false)
    end
  end
end
