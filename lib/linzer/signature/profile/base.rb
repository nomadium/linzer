# frozen_string_literal: true

module Linzer
  class Signature
    module Profile
      # Base class for all signing profiles.
      #
      # A signing profile encapsulates policy logic that can modify a
      # {Linzer::Signature::Context} before signature generation.
      #
      # Subclasses are expected to implement {#apply}.
      #
      # ## Lifecycle
      #
      # 1. Context is created
      # 2. Profile is resolved via {.resolve}
      # 3. {#apply} is invoked with the signing context
      # 4. Context is used to generate signature
      #
      # @abstract
      class Base
        # Applies the profile to a signing context.
        #
        # Implementations may:
        #
        # - modify context parameters
        # - inject overlay headers
        # - adjust covered components
        #
        # @param ctx [Linzer::Signature::Context]
        #   The mutable signing context
        #
        # @return [void]
        #
        # @raise [Linzer::Error]
        #   If the subclass does not implement this method
        def apply(ctx)
          raise Error, "Sub-classes are required to implement this method!"
        end
      end
    end
  end
end
