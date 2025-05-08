# rubocop:disable all
require_relative "lib/linzer/http/signature_feature"


if true
HTTP.default_options = HTTP::Options.new(features: {
                                           logging: {
                                             logger: Logger.new(STDOUT)
                                           }
                                         })
end

# key = Linzer.new_ed25519_key(IO.read("key"), "bar")
# #params   = {expires: Time.now.to_i + 1000, alg: "ed25519", keyid: "foo"}
# params   = {expires: Time.now.to_i + 1000, alg: "ed25519", label: "wow"}
# http     = HTTP.use(http_signatures: {key: key, params: params})
# headers  = {"Date" => Time.now.to_s}
# url      = "http://valeria.nomadium.net:9292/role"
# response = http.get(url, headers: headers)
# p response.to_s

key = Linzer.new_ed25519_key(IO.read("key"), "bar")
# #params   = {expires: Time.now.to_i + 1000, alg: "ed25519", keyid: "foo"}
params   = {expires: Time.now.to_i + 1000, alg: "ed25519", label: "wow"}
url      = "http://valeria.nomadium.net:9292/role"
response = HTTP.headers(date: Time.now.to_s)
               .use(http_signature: {key: key, params: params})
               .get(url)
binding.irb
p response.to_s
