# frozen_string_literal: true

module Linzer
  module SelfTest
    # Perform a self-test to ensure crypto primitive works as expected
    def self_test
      key_id = "self-test-key"
      blob   = "2timJEbqWumAmtlh7igcovXZ6WPVlgGL8js/3E1BcS8VqVJzKazpKDDND5GWmRFCuNZJ1c0PKzoKpfRH6ywR2Q=="
      key    = Linzer.new_hmac_sha256_key(Base64.strict_decode64(blob), key_id)

      raise SelfTestFailure.new("failed to generate key correctly") unless key.material.unpack1("H*") == "dad8a62446ea5ae9809ad961ee281ca2f5d9e963d596018bf23b3fdc4d41712f15a9527329ace92830cd0f9196991142b8d649d5cd0f2b3a0aa5f447eb2c11d9"

      message    = Linzer::Message.new({})
      components = []
      timestamp  = 1709424592
      nonce      = "VeV9xCGMxOYo7kAkkUG8iSjxhYheHjQg"
      options    = {created: timestamp, keyid: key_id, nonce: nonce}

      signature  = Linzer.sign(key, message, components, options)

      raise SelfTestFailure.new("failed to generate correct signature") unless signature.value.unpack1("H*") == "c278bc6fa8c9f2309d8bcdce62b044308a18c64975f224600691158936ea0dcf"

      raise SelfTestFailure.new("failed to verify a valid signature") unless Linzer.verify(key, message, signature)

      bad_signature = signature.to_h
      bad_signature["signature"] = "sig1=:yHifTbnnEBDlNK8z7bl9Sb/0QwdBcr0yjLzMS6pnGKwU:"
      ex = nil
      begin
        Linzer.verify(key, message, Signature.build(bad_signature))
      rescue Linzer::Error => ex
      end

      raise SelfTestFailure, "failed to detect an invalid signature" unless ex.is_a?(Linzer::Error)
    end
  end
end
