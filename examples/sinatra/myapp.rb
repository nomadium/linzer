# myapp.rb
require "sinatra"

get "/" do
  "Hello world!"
end

get "/protected" do
  "secure area"
end
