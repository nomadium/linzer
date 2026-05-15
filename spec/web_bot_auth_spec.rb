# frozen_string_literal: true

require "linzer/jws"

RSpec.xdescribe "Linzer::Options.prepare_web_bot_auth!" do
  let(:uri)       { URI("https://example.com/api/resource") }
  let(:request)   { Net::HTTP::Post.new(uri) }
  let(:message)   { Linzer::Message.new(request) }
  let(:valid_key) { Linzer::JWS.generate_key(algorithm: "EdDSA") }

  context "when no key is provided" do
    it "raises error" do
      # def prepare_web_bot_auth!(message, args, components, options)
      expect { Linzer::Options.prepare_web_bot_auth!(message, {}, [], {}) }
        .to raise_error(Linzer::Error, /invalid key/)
    end
  end

  context "when an invalid key is provided" do
    it "raises error" do
      args = {key: Linzer.generate_ed25519_key}

      expect { Linzer::Options.prepare_web_bot_auth!(message, args, [], {}) }
        .to raise_error(Linzer::Error, /invalid key/)
    end
  end

  context "when a response message is provided" do
    let(:response) { Net::HTTPOK.new("1.1", "200", "OK") }
    let(:message)  { Linzer::Message.new(response) }

    it "raises error" do
      args = {key: valid_key}

      expect { Linzer::Options.prepare_web_bot_auth!(message, args, [], {}) }
        .to raise_error(Linzer::Error, /only for requests/)
    end
  end

  context "when recommended options are requested" do
    let(:args)       { {key: valid_key, web_bot_auth: true} }
    let(:components) { [] }

    it "sets recommended values in covered components and signature options" do
      options = {}

      Linzer::Options.prepare_web_bot_auth!(message, args, components, options)

      expect(options).to         include(expires: be > Time.now.utc.to_i)
      expect(options[:tag]).to   eq("web-bot-auth")
      expect(options[:keyid]).to eq(valid_key.material.key_digest)
      expect(options).to         have_key(:nonce)
      expect(components).to      include("@authority").or include("@target-uri")
    end

    context "if a nonce value is set" do
      it "does not override the nonce" do
        options = {nonce: :something}

        Linzer::Options.prepare_web_bot_auth!(message, args, components, options)
        expect(options[:nonce]).to eq(:something)
      end
    end
  end

  context "when invalid configuration is provided" do
    let(:args)       { {key: valid_key, web_bot_auth: false} }
    let(:components) { [] }

    it "raises error" do
      options = {}

      expect { Linzer::Options.prepare_web_bot_auth!(message, args, components, options) }
        .to raise_error(Linzer::Error, /Unsupported value for web_both_auth/)
    end
  end

  context "when empty configuration is provided" do
    let(:args)       { {key: valid_key, web_bot_auth: {}} }
    let(:components) { [] }

    it "sets recommended values in covered components and signature options" do
      options = {}

      Linzer::Options.prepare_web_bot_auth!(message, args, components, options)

      expect(options).to         include(expires: be > Time.now.utc.to_i)
      expect(options[:tag]).to   eq("web-bot-auth")
      expect(options[:keyid]).to eq(valid_key.material.key_digest)
      expect(options).to         have_key(:nonce)
      expect(components).to      include("@authority").or include("@target-uri")
    end
  end

  context "when configuration is provided" do
    let(:agent)      { "https://example.com/myagent" }
    let(:components) { [] }

    context "when signature-agent is provided" do
      let(:args) { {key: valid_key, web_bot_auth: {agent: agent}} }

      it "sets the signature-agent header and add it to the covered components" do
        options = {label: "sig"}
        Linzer::Options.prepare_web_bot_auth!(message, args, components, options)

        expect(message["signature-agent"]).to eq("#{options[:label]}=\"#{agent}\"")
        # => "sig=\"https://example.com/myagent\""
        expect(components).to include("\"signature-agent\";key=\"#{options[:label]}\"")
        # => "\"signature-agent\";key=\"sig\""
      end

      context "when signature-agent is provided" do
        options = {} # invalid or missing label will cause an invalid header, for example
        it "raises error" do
          expect { Linzer::Options.prepare_web_bot_auth!(message, args, components, options) }
            .to raise_error(Linzer::Error, /Invalid signature-agent/)
        end
      end
    end

    context "when nonce generation is requested" do
      let(:args) { {key: valid_key, web_bot_auth: {nonce: :generate}} }
      it "sets the nonce option" do
        options = {}

        expect(options).to_not have_key(:nonce)
        Linzer::Options.prepare_web_bot_auth!(message, args, components, options)
        expect(options).to have_key(:nonce)
      end
    end

    context "when recommended parameters are requested" do
      let(:args) { {key: valid_key, web_bot_auth: {params: :recommended}} }

      it "sets recommended values in covered components and signature options" do
        options = {}

        Linzer::Options.prepare_web_bot_auth!(message, args, components, options)

        expect(options).to         include(expires: be > Time.now.utc.to_i)
        expect(options[:tag]).to   eq("web-bot-auth")
        expect(options[:keyid]).to eq(valid_key.material.key_digest)
        expect(components).to      include("@authority").or include("@target-uri")
      end
    end
  end
end

RSpec.describe "Linzer.sign!" do
  context "with Web Bot Auth" do
    let(:uri)     { URI("https://example.com/api/resource") }
    let(:request) { Net::HTTP::Post.new(uri) }
    let(:key)     { Linzer::JWS.generate_key(algorithm: "EdDSA") }

    it "signs the request as specified by web bot auth spec" do
      signed_request = Linzer.sign!(request,
        key:          key,
        components:   %w[@method @path],
        label:        "my-sig",
        profile:      Linzer::Signing::Profile::WebBotAuth.new(
          agent:  "https://example.com/someagent"
        ))
      headers = signed_request.each_header.to_h
      signature = Linzer::Signature.build(headers)

      expect(signature.parameters).to          include("created")
      expect(signature.parameters).to          include("expires" => be > Time.now.utc.to_i)
      expect(signature.parameters["tag"]).to   eq("web-bot-auth")
      expect(signature.parameters["keyid"]).to eq(key.material.key_digest)
      expect(signature.parameters).to          have_key("nonce")
      expect(signature.metadata).to            include('"@authority"').or include('"@target-uri"')
      expect(headers["signature-agent"]).to    eq("my-sig=\"https://example.com/someagent\"")
    end
  end
end
