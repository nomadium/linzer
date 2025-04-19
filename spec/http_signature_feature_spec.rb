# frozen_string_literal: true

require "linzer/http/signature_feature"

RSpec.describe Linzer::HTTP::SignatureFeature do
  context "when no key is provided" do
    it "does not pass validation" do
      expect { described_class.new }.to raise_error(/missing keyword: :key/)
    end
  end

  context "when a nil key is provided" do
    it "does not pass validation" do
      expect { described_class.new(key: nil) }
        .to raise_error(/Key can not be nil/)
    end
  end

  context "when a invalid key is provided" do
    it "does not pass validation" do
      expect { described_class.new(key: Object.new) }
        .to raise_error(/Key object is invalid/)
    end
  end

  context "when a valid key is provided" do
    let(:key)     { Linzer.generate_ed25519_key   }
    let(:feature) { described_class.new(key: key) }
    let(:request) do
      HTTP::Request.new(
        verb:    :post,
        uri:     "https://example.com/",
        headers: {accept: "application/json", date: Time.now.utc.to_s},
        body:    '{"hello": "world!"}'
      )
    end

    it "signs the request" do
      signed_request = feature.wrap_request(request)
      signature_headers =
        signed_request
          .headers
          .to_h
          .slice("signature", "signature-input")
      expect(signature_headers.length).to eq(2)
      expect(signature_headers.keys).to   eq(%w[signature signature-input])
    end
  end
end
