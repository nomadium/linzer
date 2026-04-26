# frozen_string_literal: true

require "linzer/faraday"

RSpec.describe Linzer::Message::Adapter::Faraday::Request do
  let(:signature) do
    Linzer::Signature.build({"signature" => "foo=:Cv1TU==:", "signature-input" => "foo=()"})
  end

  describe "#headers" do
    it "returns all headers in HTTP request message" do
      request_attrs = {method: :get, url: URI("http://example.org/something")}
      request = Linzer::Test::FaradayHelper.new_request(request_attrs)
      request.headers["Test-Header1"] = "value1"
      request.headers["header2"] = "value2"
      adapter = described_class.new(request)
      expect(adapter.header("test-header1")).to eq("value1")
      expect(adapter.header("header2")).to eq("value2")
    end
  end

  describe "#attach!" do
    it "attaches a signature to the underlying request headers" do
      request_attrs = {method: :get, url: URI("http://example.org/something")}
      request = Linzer::Test::FaradayHelper.new_request(request_attrs)
      adapter = described_class.new(request)
      adapter.attach!(signature)
      expect(adapter["signature"]).to       eq(signature.to_h["signature"])
      expect(adapter["signature-input"]).to eq(signature.to_h["signature-input"])
    end
  end

  describe "#[]" do
    context "@method" do
      it "returns the HTTP method of the request message" do
        uri = URI("https://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@method"]).to eq("POST")
      end
    end

    context "@target-uri" do
      it "returns the target URI of a request message" do
        uri = URI("https://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@target-uri"]).to eq("https://www.example.com/path?param=value")
      end
    end

    context "@authority" do
      it "returns the authority component of the target URI of the HTTP request message" do
        uri = URI("https://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@authority"]).to eq("www.example.com")
      end
    end

    context "@scheme" do
      it "returns the scheme of the target URL of the HTTP request message" do
        uri = URI("http://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@scheme"]).to eq("http")
      end
    end

    context "@request-target" do
      it "returns the full request target of the HTTP request message" do
        uri = URI("http://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@request-target"]).to eq("/path?param=value")
      end
    end

    context "@path" do
      it "returns the target path of the HTTP request message" do
        uri = URI("http://www.example.com/path?param=value")
        request_attrs = {method: :post, url: uri}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@path"]).to eq("/path")
      end
    end

    context "@query" do
      it "returns the the query component of the HTTP request message, example 1" do
        # Build the request without query params, then set the full URI
        # directly to preserve percent-encoding that Faraday would normalise
        # (e.g. %2D → -).
        full_uri = "http://www.example.com/path?param=value&foo=bar&baz=bat%2Dman"
        uri = "http://www.example.com/path"
        request_attrs = {method: :get, url: URI(uri)}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        request.path = URI(full_uri)
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?param=value&foo=bar&baz=bat%2Dman")
      end
      it "returns the the query component of the HTTP request message, example 2" do
        uri = "http://www.example.com/path?queryString"
        request_attrs = {method: :post, url: URI(uri)}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?queryString")
      end
      it "returns the the query component of the HTTP request message, example 3" do
        uri = "http://www.example.com/path"
        request_attrs = {method: :get, url: URI(uri)}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?")
      end
    end

    context "@query-param" do
      it "returns the individual query parameters of the HTTP request message" do
        uri = "http://www.example.com/path?param=value&foo=bar&baz=batman&qux="
        request_attrs = {method: :get, url: URI(uri)}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter['"@query-param";name="baz"']).to          eq("batman")
        expect(adapter['"@query-param";name="qux"']).to          eq("")
        expect(adapter['"@query-param";name="param"']).to        eq("value")
        expect(adapter['"@query-param";name="non-existent"']).to eq("")
      end
    end

    context "@invalid derived component" do
      it "returns nil" do
        uri = "http://www.example.com/path"
        request_attrs = {method: :get, url: URI(uri)}
        request = Linzer::Test::FaradayHelper.new_request(request_attrs)
        adapter = described_class.new(request)
        expect(adapter["@invalid-unknown-field-foo"]).to eq(nil)
      end
    end

    context "HTTP field" do
      context "field found in the request" do
        it "returns its value" do
          uri = "http://www.example.com/path"
          request_attrs = {method: :get, url: URI(uri)}
          request = Linzer::Test::FaradayHelper.new_request(request_attrs)
          request.headers["User-Agent"] = "linzer"
          adapter = described_class.new(request)
          expect(adapter["user-agent"]).to eq("linzer")
        end
      end
      context "field not found in the request" do
        it "returns nil" do
          uri = "http://www.example.com/path"
          request_attrs = {method: :get, url: URI(uri)}
          request = Linzer::Test::FaradayHelper.new_request(request_attrs)
          adapter = described_class.new(request)
          expect(adapter["field-not-found-foo-bar"]).to eq(nil)
        end
      end
    end
  end
end
