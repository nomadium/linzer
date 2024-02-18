# frozen_string_literal: true

RSpec.describe Linzer do
  it "has a version number" do
    expect(Linzer::VERSION).not_to be nil
  end

  it "has a ::verify method aliased to Linzer::Verifier#verify" do
    verifier = instance_double(Linzer::Verifier)
    pubkeys = {}
    message = Linzer::Message.new({})

    allow(Linzer::Verifier).to receive(:new).with(pubkeys).and_return(verifier)
    expect(verifier).to receive(:verify).with(message)

    Linzer.verify(pubkeys, message)
  end
end
