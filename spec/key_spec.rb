# frozen_string_literal: true

RSpec.describe Linzer::Key do
  let(:key) { Linzer::Key.new("key") }

  it "cannot sign data, it's an abstract class" do
    expect { key.sign(:data) }
      .to raise_error(Linzer::Error, /abstract/)
  end

  it "cannot verify signature, it's an abstract class" do
    expect { key.verify(:signature, :data) }
      .to raise_error(Linzer::Error, /abstract/)
  end
end
