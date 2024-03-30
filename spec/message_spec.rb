# frozen_string_literal: true

RSpec.describe Linzer::Message do
  describe "#request?" do
    it "returns true on a HTTP request message" do
      message = described_class.new(Rack::Request.new({}))
      expect(message.request?).to  eq(true)
      expect(message.response?).to eq(false)
    end
  end

  describe "#response?" do
    it "returns true on a HTTP response message" do
      message = described_class.new(Rack::Response.new)
      expect(message.response?).to eq(true)
      expect(message.request?).to  eq(false)
    end
  end

  describe "#[]" do
    it "returns the authority pseudo-header of an incoming request" do
      server = "www.example.org"
      request = Linzer.new_request(:get, "/foo", {}, {"Host" => server})
      message = described_class.new(request)
      expect(message["@authority"]).to eq(server)
    end

    it "returns the HTTP method of an incoming request" do
      request = Linzer.new_request(:put)
      message = described_class.new(request)
      expect(message["@method"]).to eq("PUT")
    end

    it "returns the full path of the request URI" do
      request = Linzer.new_request(:post, "/something")
      message = described_class.new(request)
      expect(message["@path"]).to eq("/something")
    end

    it "returns the status code of the response" do
      response = Linzer.new_response("body", 202, {})
      message = described_class.new(response)
      expect(message["@status"]).to eq(202)
    end

    it "returns null on undefined field on request" do
      request = Linzer.new_request(:put, "/bar", {}, {"x-foo" => "baz"})
      message = described_class.new(request)
      expect(message["x-not-in-message"]).to eq(nil)
    end
  end

  describe "#field?" do
    it "returns true if the requested field is defined on the message" do
      response = Linzer.new_response(nil, 301, {})
      message = described_class.new(response)
      expect(message.field?("@status")).to eq(true)
      expect(message["@status"]).to        be_truthy
    end

    it "returns false if the requested field is not defined on the message" do
      request = Linzer.new_request(:get, "/baz", {}, {"content-type" => "application/json"})
      message = described_class.new(request)
      expect(message.field?("x-missing")).to eq(false)
      expect(message["x-missing"]).to        be_falsey
    end
  end

  describe "#headers" do
    let(:headers) { {"content-type" => "application/json", "foo" => "bar"} }

    it "returns HTTP headers from message request" do
      request = Linzer.new_request(:options, "/foo", {}, headers)
      message = described_class.new(request)
      expect(message.request?).to eq(true)
      expect(message.headers).to  eq(headers)
    end

    it "returns HTTP headers from message response" do
      response = Linzer.new_response("body", 302, headers)
      message = described_class.new(response)
      expect(message.response?).to eq(true)
      expect(message.headers).to   eq(headers)
    end
  end

  describe "::parse_structured_dictionary" do
    it "parses HTTP structured dictionaries" do
      dict = 'sig-b26=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"'
      parsed_dict = described_class.parse_structured_dictionary(dict)

      expect(parsed_dict["sig-b26"].to_a.map(&:value))
        .to eq(%w[@status content-type content-digest content-length])
    end

    it "raises an error on unparsable strings" do
      expect { described_class.parse_structured_dictionary('puts "hello world"') }
        .to raise_error(Linzer::Error, /Cannot parse/)
    end
  end
end
