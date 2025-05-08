# rubocop:disable all
require "linzer"
require "http"

class SignatureFeature < HTTP::Feature
  def initialize(key:, params: {}, covered_components: default_components)
    @fields            = Array(covered_components)
    key_error          = "No key"
    raise HTTP::Error, key_error if !key || !key.respond_to?(:sign)
    @key               = key
    @params            = Hash(params)
  end

  HTTP::Options.register_feature(:http_signature, self)

  attr_reader :fields, :params

  def wrap_request(request)
    message = Linzer::Message.new(adapt_request(request))
    signature = Linzer.sign(key, message, fields, **params)
    request.headers.merge!(signature.to_h)
    request
  end

  def default_covered_components
    # Linzer::Options.DEFAULT_OPTIONS[:covered_components]
    %w[@method @request-target @authority date]
  end

  alias_method :default_components, :default_covered_components

  private

  attr_reader :key

  def adapt_request(request)
    env = Rack::MockRequest.env_for(request.uri)
    rack_request = Rack::Request.new(env)

    request.headers.each do |h, v|
      rack_request.set_header Linzer::Request.rack_header_name(h), v
    end

    rack_request
  end
end

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
#binding.irb
p response.to_s
