# chatgpt was going in circles, in the end JWT doesn't support signing with Ed25519 keys

require 'json/jwt'
require 'base64'

jwk_data = JSON.load(IO.read("keypair.jwk.json"))

# Step 2: Create a JWK from the signing key
jwk = JSON::JWK.new(jwk_data)

# Step 3: Sign the message using JWS
payload = "hello world"
jwt = JSON::JWT.new({data: payload})
signed_jwt = jwt.sign(jwk)

puts "\n🔐 Signed JWT:\n#{signed_jwt.to_s}"

# Step 4: Verify the signature using the public key
pub_jwk = JSON::JWK.new(jwk_data.slice("kty", "crv", "x"))

decoded_jwt = JSON::JWT.decode(signed_jws.to_s, pub_jwk)

puts "\n✅ Signature valid!"
puts "📦 Decoded payload: #{decoded_jwt['data']}"
