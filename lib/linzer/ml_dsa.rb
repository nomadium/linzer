# frozen_string_literal: true

require_relative "ml_dsa/openssl_key"
require_relative "ml_dsa/gem_key"

module Linzer
  # ML-DSA support for HTTP Message Signatures as specified by
  # https://c2sp.org/httpsig-pq
  #
  # Two independent backends live under this namespace, both supporting
  # all three FIPS 204 parameter sets (ML-DSA-44/65/87):
  #
  # - {Linzer::MLDSA::OpenSSLKey} -- backed directly by OpenSSL 3.5+, no
  #   extra gem dependency.
  # - {Linzer::MLDSA::GemKey} -- backed by the `ml_dsa` gem.
  #
  # `require "linzer"` alone already gets you OpenSSLKey for free when the
  # running OpenSSL build supports it, that's the safe default, and this
  # file plays no part in it (lib/linzer.rb requires ml_dsa/openssl_key
  # directly). `require "linzer/ml_dsa"` is the explicit opt-in for
  # everything else: it also loads GemKey, which in turn requires the
  # `ml_dsa` gem to be installed. Reach for it when your OpenSSL build is
  # too old for ML-DSA, or you specifically want the gem-backed
  # implementation.
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
