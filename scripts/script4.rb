require "linzer"

key = Linzer.new_ed25519_key(IO.read("key"))
params   = {expires: Time.now.to_i + 1000, alg: "ed25519", label: "wow"}
url      = "http://valeria.nomadium.net:9292/role"
headers = {"Date" => Time.now.utc.to_s}
# binding.irb
response = Linzer::HTTP.post(url, data: "", headers: headers, key: key)
# response = Linzer::HTTP.get(url, headers: headers, key: key)
p response
p response.body.to_s
# binding.irb
