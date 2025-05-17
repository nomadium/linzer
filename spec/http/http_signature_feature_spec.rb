# frozen_string_literal: true

require "linzer/http/bootstrap"

RSpec.describe "Linzer::HTTP::SignatureFeature" do
  let(:described_class) { Linzer::HTTP::SignatureFeature }

  context "when http gem is not found" do
    it "raises Linzer::Error" do
      allow(Linzer::HTTP::Bootstrap).to receive(:require_dependencies)
        .and_raise(LoadError)
      expect { require "linzer/http/signature_feature" }
        .to raise_error(Linzer::Error, /http gem is required to be installed/)
    end
  end

  context "when http gem is installed" do
    before do
      require "linzer/http/signature_feature"
    end

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
      let(:key)     { Linzer.generate_ed25519_key }
      let(:pubkey)  { Linzer.new_ed25519_key(key.material.public_to_pem) }
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
        signature      = Linzer::Signature.build(signed_request.headers.to_h)

        expect(signature).to be_instance_of(Linzer::Signature)
        expect(Linzer.verify!(request, key: pubkey)).to eq(true)
      end
    end
  end
end
