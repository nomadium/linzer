# frozen_string_literal: true

module Linzer
  module Signing
    module Profile
      class WebBotAuth < Base
        # def apply(ctx)
        #   binding.irb
        # end

        def self.default
          new
        end
      end
    end
  end
end
