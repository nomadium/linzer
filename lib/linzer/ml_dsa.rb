# frozen_string_literal: true

require_relative "ml_dsa/openssl_key"

module Linzer
  # ML-DSA support for HTTP Message Signatures as specified by https://c2sp.org/httpsig-pq
  #
  # Two independent backends live under this namespace:
  #
  # - {Linzer::MLDSA::OpenSSLKey} -- ML-DSA-44 only, backed directly by
  #   OpenSSL 3.5+, no extra gem dependency. Always loaded by this file.
  # - {Linzer::MLDSA::GemKey} -- all three FIPS 204 parameter sets, backed
  #   by the `ml_dsa` gem. Optional: `require "ml_dsa"` and
  #   `require "linzer/ml_dsa/gem_key"` yourself to use it.
  #
  # Neither backend is wired into the `Linzer.generate_ml_dsa_*_key`/
  # `Linzer.new_ml_dsa_*_key` helpers being preferred over the other yet.
  #
  # @see https://c2sp.org/httpsig-pq C2SP post-quantum HTTP signatures
  # @see https://csrc.nist.gov/pubs/fips/204/final FIPS 204
  module MLDSA
  end
end
