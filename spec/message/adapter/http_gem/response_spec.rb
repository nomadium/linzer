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

  context "fixed bugs" do
    let(:message) { Linzer::Message.new(response) }

    describe "https://github.com/nomadium/linzer/issues/16" do
      it "should not raise error when looking up the @status derived field id in its serialized form" do
        expect { message['"@status"'] }.to_not raise_error
        expect(message['"@status"']).to        eq(200)
      end
    end
  end
end
