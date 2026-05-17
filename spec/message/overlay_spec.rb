# frozen_string_literal: true

RSpec.describe Linzer::Message::Overlay do
  let(:request) do
    headers = {
      "Host"         => "example.com",
      "User-Agent"   => "linzer",
      "Content-Type" => "application/json"
    }
    req = Net::HTTP::Get.new(URI("https://example.com/bot"))
    req.initialize_http_header(headers.to_h)
    req
  end

  let(:message) { Linzer::Message.new(request) }

  let(:overlay_headers) do
    {
      "Signature-Agent" => "https://example.org/bot",
      "X-Extra"         => "overlay-value",
      "User-Agent"      => "overlay-agent"
    }
  end

  subject(:overlay) do
    described_class.new(message, overlay_headers)
  end

  describe "#header" do
    it "returns headers from the underlying message first" do
      expect(overlay.header("user-agent")).to eq("linzer")
    end

    it "falls back to overlay headers when the header is missing" do
      expect(overlay.header("x-extra")).to eq("overlay-value")
    end

    it "returns nil when neither message nor overlay contain the header" do
      expect(overlay.header("x-missing")).to be_nil
    end
  end

  describe "#field?" do
    it "returns true for fields present in the underlying message" do
      content_type = Linzer::FieldId.new(field_name: "content-type")

      expect(overlay.field?(content_type)).to be(true)
    end

    it "returns true for non-derived fields present in overlay headers" do
      x_extra = Linzer::FieldId.new(field_name: "x-extra")
      expect(overlay.field?(x_extra)).to be(true)
    end

    it "returns false for derived fields not present in the message" do
      query_param = Linzer::FieldId.new(field_name: '"@query-param";name="baz"')
      expect(overlay.field?(query_param)).to be(false)
    end

    it "does not resolve derived fields from overlay headers" do
      derived = Linzer::FieldId.new(field_name: "@authority")
      expect(overlay.field?(derived)).to eq(message.field?(derived))
    end
  end

  describe "#[]" do
    it "returns values from the underlying message first" do
      expect(overlay["user-agent"]).to eq("linzer")
    end

    it "falls back to overlay headers for non-derived fields" do
      expect(overlay["x-extra"]).to eq("overlay-value")
    end

    it "returns nil for unknown fields" do
      expect(overlay["x-missing"]).to be_nil
    end

    it "does not resolve derived components from overlay headers" do
      expect(overlay["@method"]).to eq(message["@method"])
    end

    it "does not allow overlay values to override derived fields" do
      custom_overlay = described_class.new(
        message,
        "@method" => "POST"
      )
      expect(custom_overlay["@method"]).to eq("GET")
    end
  end

  describe "#attach!" do
    let(:signature) do
      Linzer::Signature.build(
        "Signature"       => "sig1=:abc123=:",
        "Signature-Input" => 'sig1=("@method");created=123'
      )
    end

    it "attaches signature headers to the underlying message" do
      overlay.attach!(signature)
      expect(message.header("signature")).to       include("sig1")
      expect(message.header("signature-input")).to include("sig1")
    end

    it "attaches overlay headers to the underlying message" do
      overlay.attach!(signature)
      expect(message.header("signature-agent")).to eq("https://example.org/bot")
      expect(message.header("x-extra")).to         eq("overlay-value")
    end

    it "does not override existing message headers with overlay values" do
      overlay.attach!(signature)
      expect(message.header("user-agent")).to eq("overlay-agent")
    end

    it "returns the underlying message operation result" do
      result = overlay.attach!(signature)
      expect(result).to eq(request)
    end
  end
end
