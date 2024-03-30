# frozen_string_literal: true

RSpec.describe Linzer::Request do
  describe "::build" do
    it "fails to build a request with an invalid HTTP method" do
      expect { described_class.build(:unknown, "/foo", {}, {"bar" => "baz"}) }
        .to raise_error(Linzer::Error, /[uU]nknown.+HTTP request method/)
    end

    it "fails to build a request with an invalid params" do
      expect { Linzer::Request.build(:get, "/foo", :invalid_params, {"bar" => "baz"}) }
        .to raise_error(Linzer::Error, /invalid "params" parameter/)
    end

    it "fails to build a request with an invalid headers" do
      expect { Linzer::Request.build(:post, "/hello", {}, :invalid_headers) }
        .to raise_error(Linzer::Error, /invalid "headers" parameter/)
    end

    it "fails to build a request with an invalid uri" do
      expect { Linzer::Request.build(:head, %w[invalid_uri], {}, {"bar" => "baz"}) }
        .to raise_error(Linzer::Error, /[iI]nvalid URI/)
    end

    it "builds a Rack::Request instance" do
      request = Linzer::Request.build(:options, "/example", {}, {"bar" => "baz"})
      expect(request.is_a?(Rack::Request)).to   eq(true)
      expect(request.request_method).to         eq("OPTIONS")
      expect(request.path_info).to              eq("/example")
      expect(request.get_header("HTTP_BAR")).to eq("baz")
      expect(request.params).to                 eq({})
    end
  end

  describe "::rack_header_name" do
    it "returns the expected Rack header name for Content-Type header" do
      expect(described_class.rack_header_name("Content-Type")).to eq("CONTENT_TYPE")
    end

    it "returns the expected Rack header name for Content-Length header" do
      expect(described_class.rack_header_name("Content-Length")).to eq("CONTENT_LENGTH")
    end

    it "returns the expected Rack header name for any other header" do
      expect(described_class.rack_header_name("X-Something")).to eq("HTTP_X_SOMETHING")
    end

    it "is case insensitive" do
      expect(described_class.rack_header_name("content-type")).to eq("CONTENT_TYPE")
    end

    it "fails with null" do
      expect { described_class.rack_header_name(nil) }
        .to raise_error(Linzer::Error, /Invalid header name/)
    end

    it "fails with an empty string" do
      expect { described_class.rack_header_name("") }
        .to raise_error(Linzer::Error, /Invalid header name/)
    end

    it "fails with an arbitrary object" do
      expect { described_class.rack_header_name(Object.new) }
        .to raise_error(Linzer::Error, /Invalid header name/)
    end
  end

  describe "::headers" do
    let(:headers) do
      {
        "content-digest" => "...",
        "content-type"   => "application/json",
        "user-agent"     => "Ruby",
        "x-foo"          => "bar"
      }
    end

    it "returns Rack::Request HTTP headers in canonical form" do
      request = described_class.build(:put, "/example", {}, headers)
      expect(described_class.headers(request)).to eq(headers)
    end
  end
end
