# myapp.rb
require "sinatra"

get "/" do
  "Hello world!"
end

get "/protected" do
  # if signature is valid, rack will expose it in the request object,
  # so application specific checks can be performed, e.g.:
  #
  # halt if !request.env["rack.signature"].parameters["nonce"]
  # halt if redis.exists?(request.env["rack.signature"].parameters["nonce"])
  # halt unless request.env["rack.signature"].parameters["tag"] == "myapp"
  #
  # Note that these examples are deliberately simple for illustration
  # purposes since such validations would make more sense to be
  # encapsulated in helper methods called in a before { ... } block.
  #
  "secure area"
end
