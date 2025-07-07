# frozen_string_literal: true

module Linzer::Message::Adapter
  module Foo
    class IncompleteRequest < Generic::Request
    end
  end
end

RSpec.describe Linzer::Message::Adapter::Foo::IncompleteRequest do
  describe "[]" do
    it "doesn't implement lookup for derived field @method" do
      message = described_class.new(:request)
      expect { message["@method"] }.to raise_error(Linzer::Error, /not implemented/)
    end
  end
end
