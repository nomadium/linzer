require 'json/jwt'
require 'ed25519'
require 'base64'

# Helper to base64url decode
def b64url_decode(str)
  str += '=' * (4 - str.length % 4) unless str.length % 4 == 0
  Base64.urlsafe_decode64(str)
end

# Load JWK using json-jwt
jwk = JSON::JWK.new(JSON.load(IO.read("keypair.jwk.json")))

# some signature
signature = "ntl7AjMNYEBlHeGAv1mAG+/eWcOnnVC5/2v4wg4kkUBcr+mitF3Hrz+Voh639LJCOQUwfTuScKy5PbLXMMygBw=="
# puts "Signature (Base64): #{Base64.strict_encode64(signature)}"

# Extract raw key bytes
private_key_seed = b64url_decode(jwk[:d])
public_key_bytes = b64url_decode(jwk[:x])

# Create key objects with ed25519 gem
# signing_key = Ed25519::SigningKey.new(private_key_seed)
verify_key = Ed25519::VerifyKey.new(public_key_bytes)

# Message to sign
message = "hello world"

# Sign message
# signature = signing_key.sign(message)

# puts "Signature (Base64): #{Base64.strict_encode64(signature)}"

# === Verification ===
begin
  verify_key.verify(Base64.strict_decode64(signature), message)
  puts "✅ Signature is valid"
rescue Ed25519::VerifyError
  puts "❌ Invalid signature"
end
