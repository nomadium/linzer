# frozen_string_literal: true

module Linzer
  module Signature
    module Profile
      # Example no-op signing profile.
      #
      # This profile exists solely for documentation and testing purposes.
      # It does not modify the signing context in any way.
      #
      # It demonstrates the expected structure of a signing profile:
      #
      # - initializer receives configuration parameters
      # - {#apply} mutates a {Linzer::Signature::Context}
      #
      # This profile is safe to use but has no effect on signature output.
      class Example < Base
        # Creates a new example profile instance.
        #
        # @param foo [Object] example configuration parameter (unused)
        # @param bar [Object] example configuration parameter (unused)
        def initialize(foo:, bar:)
          @foo = foo
          @bar = bar
        end

        # Applies this profile to the signing context.
        #
        # This implementation intentionally performs no modifications.
        #
        # @param ctx [Linzer::Signature::Context]
        # @return [void]
        def apply(ctx)
          # no-op
        end
      end
    end
  end
end
