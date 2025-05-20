# frozen_string_literal: true

RSpec.describe Linzer::Message::Adapter::NetHTTP::Response do
  describe "#headers" do
    it "returns all headers in HTTP response message" do
      response = Net::HTTPOK.new("1.1", "200", "OK")
      response["Test-Header1"] = "value1"
      response["header2"] = "value2"
      adapter = described_class.new(response)
      expect(adapter.header("test-header1")).to eq("value1")
      expect(adapter.header("header2")).to eq("value2")
    end
  end

  describe "#attach!" do
    it "attaches a signature to the underlying response headers" do
      signature_data = {"signature" => "foo=:Cv1TU==:", "signature-input" => "foo=()"}
      signature = Linzer::Signature.build(signature_data)
      response = Net::HTTPOK.new("1.1", "200", "OK")
      adapter = described_class.new(response)
      adapter.attach!(signature)
      expect(adapter["signature"]).to       eq(signature.to_h["signature"])
      expect(adapter["signature-input"]).to eq(signature.to_h["signature-input"])
    end
  end

  describe "#[]" do
    context "@status" do
      it "returnd the three-digit numeric HTTP status code of a response message" do
        status = "201"
        response = Net::HTTPOK.new("1.1", status, "OK")
        adapter = described_class.new(response)
        expect(adapter["@status"]).to eq(status.to_i)
      end
    end

    context "HTTP field" do
      context "field found in the request" do
        it "returns its value" do
          response = Net::HTTPOK.new("1.1", 200, "OK")
          response["header1"] = "value1"
          adapter = described_class.new(response)
          expect(adapter["header1"]).to eq("value1")
        end
      end

      context "field not found in the request" do
        it "returns nil" do
          response = Net::HTTPOK.new("1.1", 200, "OK")
          adapter = described_class.new(response)
          expect(adapter["field-not-found-foo-bar"]).to eq(nil)
        end
      end
    end
  end
end
