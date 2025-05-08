# rubocop:disable all
require "linzer"
require "net/http"

def get(key, uri, headers, fields, host, port, **opts)
  request = Linzer.new_request(:get, uri, {}, headers)
  message = Linzer::Message.new(request)
  signature = Linzer.sign(key, message, fields)

  http = Net::HTTP.new(host, port)
  http.set_debug_output($stderr) if opts[:debug]
  http.get(uri, headers.merge(signature.to_h))
end

key = Linzer.new_ed25519_key(IO.read("key"))
headers = { "date" => Time.now.utc.to_s }
fields = %w[@method @request-target date]
host = "valeria.nomadium.net"
port = 9292

response = get(key, "/role", headers, fields, host, port)
pp response.body
