require 'rbnacl'
require 'jose'

# Step 2: Create a JWK from the signing key
jwk = JOSE::JWK.generate_key([:okp, :Ed25519])

# Step 3: Sign the message using JWS
payload = "hello world"
jws = JOSE::JWS.sign(jwk, payload, { "alg" => 'Ed25519' })
compact_jws = jws.compact

puts "\n🔐 Compact JWS:\n#{compact_jws}"

# Step 4: Verify the signature using the public key
pub_jwk = jwk.to_public
verified, verified_payload, _headers = JOSE::JWS.verify(pub_jwk, compact_jws)

puts "\n✅ Signature valid: #{verified}"
puts "📦 Payload: #{verified_payload}"
