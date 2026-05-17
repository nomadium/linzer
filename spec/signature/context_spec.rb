# frozen_string_literal: true

RSpec.describe Linzer::Signature::Context do
  let(:request) do
    headers = {
      "Host"         => "example.com",
      "Content-Type" => "application/json"
    }
    req = Net::HTTP::Post.new(URI("https://example.com/foo"))
    req.initialize_http_header(headers.to_h)
    req
  end

  let(:message) { Linzer::Message.new(request) }

  let(:key) do
    instance_double("Linzer::Key")
  end

  let(:components) do
    %w[@method @path content-type]
  end

  let(:params) do
    {
      created: 1234567890,
      nonce:   "abc123"
    }
  end

  subject(:context) do
    described_class.new(
      message:    message,
      key:        key,
      label:      label,
      components: components,
      params:     params
    )
  end

  describe "#initialize" do
    let(:label) { nil }

    it "stores the signing key" do
      expect(context.key).to eq(key)
    end

    it "duplicates components" do
      expect(context.components).to     eq(components)
      expect(context.components).not_to be(components)
    end

    it "duplicates params" do
      expect(context.params).to     eq(params)
      expect(context.params).not_to be(params)
    end

    it "initializes overlay headers as an empty hash" do
      expect(context.overlay_headers).to eq({})
    end

    it "does not mutate the original components array" do
      context.components << "@authority"
      expect(components).to eq(%w[@method @path content-type])
    end

    it "does not mutate the original params hash" do
      context.params[:tag] = "web-bot-auth"
      expect(params).to eq(
        created: 1234567890,
        nonce:   "abc123"
      )
    end

    context "when a label is provided" do
      let(:label) { "sig1" }

      it "merges the label into params" do
        expect(context.params[:label]).to eq("sig1")
      end

      it "preserves existing params" do
        expect(context.params[:created]).to eq(1234567890)
        expect(context.params[:nonce]).to   eq("abc123")
      end

      it "does not mutate the original params hash" do
        expect(params).not_to have_key(:label)
      end
    end

    context "when no label is provided" do
      let(:label) { nil }

      it "does not add a label param" do
        expect(context.params).not_to have_key(:label)
      end
    end
  end

  describe "#message" do
    let(:label) { nil }

    context "when no overlay headers are present" do
      it "returns the original message" do
        expect(context.message).to eq(message)
      end

      it "returns the same object on repeated calls" do
        expect(context.message).to be(context.message)
      end
    end

    context "when overlay headers are present" do
      before do
        context.overlay_headers["signature-agent"] =
          "https://example.org/bot"
      end

      it "returns an overlay message" do
        expect(context.message).to be_a(Linzer::Message::Overlay)
      end

      it "uses overlay headers in the derived message view" do
        expect(context.message.header("signature-agent"))
          .to eq("https://example.org/bot")
      end

      it "preserves headers from the original message" do
        expect(context.message.header("content-type"))
          .to eq("application/json")
      end

      it "memoizes the overlay message" do
        expect(context.message).to be(context.message)
      end

      it "does not mutate the original message" do
        expect(message.header("signature-agent")).to be_nil
      end
    end
  end
end
