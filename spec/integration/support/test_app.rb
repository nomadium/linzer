require "sinatra"

module Linzer
  module Test
    class TestApp < Sinatra::Base
      get "/" do
        key = Linzer.generate_ed25519_key
        response = Rack::Response.new
        # response.status = 200
        response["bar"] = "header foo"
        response["Baz"] = "header ugh?"

        # message = Linzer::Message.new(response)
        # binding.irb

        # if response.class == String # false
        if true
          Linzer.sign!(
            response,
            key: key,
            components: %w[@status bar baz],
            label: "sig1",
            params: {
              created: Time.now.to_i
            }
          )
        end

        # "Hello world sinatra!"
        response.finish
      end
    end
  end
end
