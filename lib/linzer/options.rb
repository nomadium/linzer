# frozen_string_literal: true

module Linzer
  # Default configuration options for HTTP message signatures.
  #
  # These defaults provide a reasonable starting point for most applications.
  # They can be overridden when signing or in middleware configuration.
  module Options
    # Default configuration values.
    #
    # @return [Hash] Frozen hash of default options
    #
    # @option DEFAULT [Array<String>] :covered_components Default components
    #   to include in signatures: `@method`, `@request-target`, `@authority`,
    #   and `date`. These provide good baseline security for most use cases.
    #
    # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.1 RFC 9421 Section 7.2.1
    DEFAULT = {
      covered_components: %w[@method @request-target @authority date]
    }.freeze
  end
end
