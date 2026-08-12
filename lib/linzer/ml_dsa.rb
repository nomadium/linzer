# frozen_string_literal: true

require_relative "ml_dsa/openssl_key"

module Linzer
  # ML-DSA support for HTTP Message Signatures as specified by https://c2sp.org/httpsig-pq
  #
  # Two independent backends live under this namespace, both supporting
  # all three FIPS 204 parameter sets (ML-DSA-44/65/87):
  #
  # - {Linzer::MLDSA::OpenSSLKey} -- backed directly by OpenSSL 3.5+, no
  #   extra gem dependency. Always loaded by this file.
  # - {Linzer::MLDSA::GemKey} -- backed by the `ml_dsa` gem. Optional:
  #   `require "linzer/ml_dsa/gem_key"` yourself to use it (which
  #   requires `ml_dsa` in turn).
  #
  # `Linzer.generate_ml_dsa_*_key`/`Linzer.new_ml_dsa_*_key` dispatch
  # between them via a `backend:` keyword (:auto, :openssl, or :ml_dsa),
  # preferring OpenSSL when this build actually supports it.
  #
  # @see https://c2sp.org/httpsig-pq C2SP post-quantum HTTP signatures
  # @see https://csrc.nist.gov/pubs/fips/204/final FIPS 204
  module MLDSA
  end
end
