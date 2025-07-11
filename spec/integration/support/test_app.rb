# frozen_string_literal: true

require "sinatra"
require "starry"
require "digest"
require "json"
require "base64"
require "ed25519"
require "linzer/jws"

module Linzer
  module Test
    class TestApp < Sinatra::Base
      configure do
        set :app_key, Linzer.generate_jws_key(algorithm: "EdDSA")
      end

      after do
        set_content_digest!
        sign!
      end

      get "/" do
        "Hello, world!\n"
      end

      get "/.well-known/http-message-signatures-directory" do
        content_type "application/http-message-signatures-directory"
        keys_directory.to_json
      end

      helpers do
        def app_key_params
          now = Time.now.to_i
          {nbf: (now - 500) * 1000, exp: (now + 3600) * 1000}
        end

        def app_jwk_key
          settings.app_key.material
        end

        def app_verify_key
          settings.app_key.material.verify_key
        end

        def kid
          app_jwk_key.export[:kid]
        end

        def set_content_digest!
          response["content-digest"] = content_digest(response.body.join)
        end

        def content_digest(data)
          Starry.serialize("sha-256" => Digest::SHA256.digest(data))
        end

        def keys_directory
          # https://datatracker.ietf.org/doc/html/rfc7517#section-4
          jwk = app_jwk_key
          {
            "keys"    => [jwk.export.merge(app_key_params)],
            "purpose" => "rag"
          }
        end

        def sign!
          Linzer.sign!(
            response,
            key:        settings.app_key,
            components: %w[@status content-digest],
            label: "sig1",
            params: {
              created: Time.now.to_i,
              keyid:   kid
            }
          )
        end
      end
    end
  end
end
