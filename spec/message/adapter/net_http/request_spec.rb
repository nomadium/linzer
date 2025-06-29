# frozen_string_literal: true

RSpec.describe Linzer::Message::Adapter::NetHTTP::Request do
  let(:signature) do
    Linzer::Signature.build({"signature" => "foo=:Cv1TU==:", "signature-input" => "foo=()"})
  end

  describe "#headers" do
    it "returns all headers in HTTP request message" do
      request = Net::HTTP::Get.new(URI("http://example.org/something"))
      request["Test-Header1"] = "value1"
      request["header2"] = "value2"
      adapter = described_class.new(request)
      expect(adapter.header("test-header1")).to eq("value1")
      expect(adapter.header("header2")).to eq("value2")
    end
  end

  describe "#attach!" do
    it "attaches a signature to the underlying request headers" do
      request = Net::HTTP::Get.new(URI("http://example.org/something"))
      adapter = described_class.new(request)
      adapter.attach!(signature)
      expect(adapter["signature"]).to       eq(signature.to_h["signature"])
      expect(adapter["signature-input"]).to eq(signature.to_h["signature-input"])
    end
  end

  describe "#[]" do
    context "@method" do
      it "returns the HTTP method of the request message" do
        request = Net::HTTP::Post.new(URI("https://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@method"]).to eq("POST")
      end
    end

    context "@target-uri" do
      it "returns the target URI of a request message" do
        request = Net::HTTP::Post.new(URI("https://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@target-uri"]).to eq("https://www.example.com/path?param=value")
      end
    end

    context "@authority" do
      it "returns the authority component of the target URI of the HTTP request message" do
        request = Net::HTTP::Post.new(URI("https://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@authority"]).to eq("www.example.com")
      end
    end

    context "@scheme" do
      it "returns the scheme of the target URL of the HTTP request message" do
        request = Net::HTTP::Post.new(URI("http://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@scheme"]).to eq("http")
      end
    end

    context "@request-target" do
      it "returns the full request target of the HTTP request message" do
        request = Net::HTTP::Post.new(URI("http://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@request-target"]).to eq("/path?param=value")
      end
    end

    context "@path" do
      it "returns the target path of the HTTP request message" do
        request = Net::HTTP::Post.new(URI("http://www.example.com/path?param=value"))
        adapter = described_class.new(request)
        expect(adapter["@path"]).to eq("/path")
      end
    end

    context "@query" do
      it "returns the the query component of the HTTP request message, example 1" do
        uri = "http://www.example.com/path?param=value&foo=bar&baz=bat%2Dman"
        request = Net::HTTP::Get.new(URI(uri))
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?param=value&foo=bar&baz=bat%2Dman")
      end
      it "returns the the query component of the HTTP request message, example 2" do
        uri = "http://www.example.com/path?queryString"
        request = Net::HTTP::Post.new(URI(uri))
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?queryString")
      end
      it "returns the the query component of the HTTP request message, example 3" do
        uri = "http://www.example.com/path"
        request = Net::HTTP::Get.new(URI(uri))
        adapter = described_class.new(request)
        expect(adapter["@query"]).to eq("?")
      end
    end

    context "@query-param" do
      it "returns the individual query parameters of the HTTP request message" do
        uri = "http://www.example.com/path?param=value&foo=bar&baz=batman&qux="
        request = Net::HTTP::Get.new(URI(uri))
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
        request = Net::HTTP::Get.new(URI(uri))
        adapter = described_class.new(request)
        expect(adapter["@invalid-unknown-field-foo"]).to eq(nil)
      end
    end

    context "HTTP field" do
      context "field found in the request" do
        it "returns its value" do
          uri = "http://www.example.com/path"
          request = Net::HTTP::Get.new(URI(uri))
          adapter = described_class.new(request)
          expect(adapter["user-agent"]).not_to be_empty
        end
      end
      context "field not found in the request" do
        it "returns nil" do
          uri = "http://www.example.com/path"
          request = Net::HTTP::Get.new(URI(uri))
          adapter = described_class.new(request)
          expect(adapter["field-not-found-foo-bar"]).to eq(nil)
        end
      end
    end
  end
end
