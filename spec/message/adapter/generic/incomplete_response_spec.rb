# frozen_string_literal: true

module Linzer::Message::Adapter
  module Foo
    class IncompleteResponse < Generic::Response
    end
  end
end

RSpec.describe Linzer::Message::Adapter::Foo::IncompleteResponse do
  describe "[]" do
    it "doesn't implement lookup for derived fields" do
      message = described_class.new(:response)

      expected_error = /required to implement/

      expect { message["@status"] }.to raise_error(Linzer::Error, expected_error)
      expect { message["@foobar"] }.to raise_error(Linzer::Error, expected_error)
    end
  end
end
