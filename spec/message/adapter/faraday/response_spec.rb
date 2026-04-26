# frozen_string_literal: true

RSpec.describe "Linzer::Message::Adapter::Faraday::Response" do
  before(:all) do
    require "linzer/faraday"
  end

  let(:response_headers) do
    {
      "Test-Header1" => "value1",
      "header2"      => "value2"
    }
  end

  let(:response) do
    env = Faraday::Env.new(status: 200, response_headers: response_headers)
    Faraday::Response.new(env)
  end

  let(:adapter) { Linzer::Message::Adapter::Faraday::Response.new(response) }

  describe "#headers" do
    it "returns all headers in HTTP response message" do
      expect(adapter.header("test-header1")).to eq("value1")
      expect(adapter.header("header2")).to      eq("value2")
    end
  end

  describe "#attach!" do
    it "attaches a signature to the underlying response headers" do
      signature_data = {"signature" => "foo=:Cv1TU==:", "signature-input" => "foo=()"}
      signature = Linzer::Signature.build(signature_data)
      adapter.attach!(signature)
      expect(adapter["signature"]).to       eq(signature.to_h["signature"])
      expect(adapter["signature-input"]).to eq(signature.to_h["signature-input"])
    end
  end

  describe "#[]" do
    context "@status" do
      it "returns the three-digit numeric HTTP status code of a response message" do
        status = 200
        expect(adapter["@status"]).to eq(status)
      end
    end

    context "HTTP field" do
      context "field found in the request" do
        it "returns its value" do
          expect(adapter["test-header1"]).to eq("value1")
        end
      end

      context "field not found in the request" do
        it "returns nil" do
          expect(adapter["field-not-found-foo-bar"]).to eq(nil)
        end
      end
    end
  end
end
