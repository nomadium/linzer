# frozen_string_literal: true

module Linzer
  module Options
    DEFAULT = {
      covered_components: %w[@method @request-target @authority date]
    }.freeze
  end
end
