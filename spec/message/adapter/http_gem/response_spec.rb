# frozen_string_literal: true

RSpec.describe "Linzer::Message::Adapter::HTTPGem::Response" do
  before(:all) do
    require "http"
    require "linzer/message/adapter/http_gem/response"
    Linzer::Message
      .register_adapter(HTTP::Response,
                        Linzer::Message::Adapter::HTTPGem::Response)
  end

  let(:uri) { URI.parse("https://example.com/") }

  let(:request) do
    HTTP::Request.new(
      verb:    :get,
      uri:     uri,
      headers: HTTP::Headers.coerce({}),
      body:    nil
    )
  end

  let(:response_headers) do
    {
      "Test-Header1" => "value1",
      "header2"      => "value2"
    }
  end

  let(:response) do
    HTTP::Response.new(
      status:  200,
      version: "1.1",
      headers: HTTP::Headers.coerce(response_headers),
      body:    "something",
      request: request
    )
  end

  let(:adapter) { Linzer::Message::Adapter::HTTPGem::Response.new(response) }

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
      it "returnd the three-digit numeric HTTP status code of a response message" do
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

  context "fixed bugs" do
    describe "https://github.com/nomadium/linzer/issues/16" do
      let(:message) { Linzer::Message.new(response) }

      it "should not raise error when looking up the @status derived field id in its serialized form" do
        expect { message['"@status"'] }.to_not raise_error
        expect(message['"@status"']).to        eq(200)
      end
    end
  end
end
