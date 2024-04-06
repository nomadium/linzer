# frozen_string_literal: true

RSpec.describe Linzer do
  it "has a version number" do
    expect(Linzer::VERSION).not_to be nil
  end

  it "has a ::verify method aliased to Linzer::Verifier::verify" do
    pubkey    = :some_key
    message   = Linzer::Message.new(Linzer.new_request(:get))
    signature = :some_signature

    expect(Linzer::Verifier).to receive(:verify)
      .with(pubkey, message, signature)

    Linzer.verify(pubkey, message, signature)
  end

  it "has a ::sign method aliased to Linzer::Signer::sign" do
    key = Linzer.generate_rsa_pss_sha512_key(2048)
    message    = :message
    components = []
    options    = {}

    expect(Linzer::Signer).to receive(:sign)
      .with(key, message, components, options)

    Linzer.sign(key, message, components, options)
  end

  it "has a ::new_request method aliased to Linzer::Request::build" do
    uri     = "/some_uri"
    params  = {}
    headers = {"foo" => "bar"}

    expect(Linzer::Request).to receive(:build)
      .with(:get, uri, params, headers)

    Linzer.new_request(:get, uri, params, headers)
  end

  it "has a ::new_response method aliased to Rack::Response::initialize" do
    expect(Rack::Response).to receive(:new)
      .with(:body, :status, {})

    Linzer.new_response(:body, :status, {})
  end
end
