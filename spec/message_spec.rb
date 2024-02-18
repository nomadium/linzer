# frozen_string_literal: true

RSpec.describe Linzer::Message do
  let(:message) { Linzer::Message.new({}) }

  it "is not null" do
    expect(message).to_not eq(nil)
  end

  # XXX: to-do: write real tests here
end
