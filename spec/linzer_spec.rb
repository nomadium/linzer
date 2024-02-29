# frozen_string_literal: true

RSpec.describe Linzer do
  it "has a version number" do
    expect(Linzer::VERSION).not_to be nil
  end

  it "has a ::verify method aliased to Linzer::Verifier::verify" do
    pubkey    = :some_key
    message   = Linzer::Message.new(headers: {})
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
end
