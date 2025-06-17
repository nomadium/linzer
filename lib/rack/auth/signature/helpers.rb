# frozen_string_literal: true

require "yaml"

module Rack
  module Auth
    class Signature
      module Helpers
        module Parameters
          private

          def created?
            !options[:signatures][:created_required] || !!Integer(params.fetch("created"))
          end

          def expires?
            return true if !options[:signatures][:expires_required]
            Integer(params.fetch("expires")) > Time.now.to_i
          end

          def keyid?
            !options[:signatures][:keyid_required] || String(params.fetch("keyid"))
          end

          def nonce?
            !options[:signatures][:nonce_required] || String(params.fetch("nonce"))
          end

          def alg?
            !options[:signatures][:alg_required] || String(params.fetch("alg"))
          end

          def tag?
            !options[:signatures][:tag_required] || String(params.fetch("tag"))
          end
        end

        module Configuration
          DEFAULT_OPTIONS = {
            signatures: {
              reject_older_than:  900,
              created_required:   true,
              nonce_required:     false,
              alg_required:       false,
              tag_required:       false,
              expires_required:   false,
              keyid_required:     false,
              covered_components: %w[@method @request-target @authority date],
              error_response:     {body: [], status: 401, headers: {}}
            },
            keys: {}
          }

          private_constant :DEFAULT_OPTIONS

          private

          def load_options(options)
            options_from_file = load_options_from_config_file(options)
            {
              except:      options[:except]      || options_from_file[:except],
              default_key: options[:default_key] || options_from_file[:default_key],
              signatures:
                DEFAULT_OPTIONS[:signatures]
                  .merge(options_from_file[:signatures].to_h)
                  .merge(options[:signatures].to_h),
              keys:
                DEFAULT_OPTIONS[:keys]
                  .merge(options_from_file[:keys].to_h)
                  .merge(options[:keys].to_h)
            }
          end

          def load_options_from_config_file(options)
            config_path = options[:config_path]
            YAML.safe_load_file(config_path, symbolize_names: true)
          rescue
            {}
          end
        end

        module Key
          private

          def key
            build_key(params["keyid"])
          end

          def build_key(keyid)
            key_data = if keyid.nil? ||
                (!options[:keys].key?(keyid.to_sym) && options[:default_key])
              options[:default_key].to_h
            else
              options[:keys][keyid.to_sym] || {}
            end

            if key_data.key?(:path) && !key_data.key?(:material)
              key_data[:material] = IO.read(key_data[:path]) rescue nil
            end

            if !key_data || key_data.empty? || !key_data[:material]
              key_not_found = "Key not found. Signature cannot be verified."
              raise Linzer::Error.new key_not_found
            end

            alg = @signature.parameters["alg"] || key_data[:alg] || :unknown
            instantiate_key(keyid || :default, alg, key_data)
          end

          def instantiate_key(keyid, alg, key_data)
            key_methods = {
              "rsa-pss-sha512"    => :new_rsa_pss_sha512_key,
              "rsa-v1_5-sha256"   => :new_rsa_v1_5_sha256_key,
              "hmac-sha256"       => :new_hmac_sha256_key,
              "ecdsa-p256-sha256" => :new_ecdsa_p256_sha256_key,
              "ecdsa-p384-sha384" => :new_ecdsa_p384_sha384_key,
              "ed25519"           => :new_ed25519_public_key
            }
            method = key_methods[alg]

            alg_error = "Unsupported or unknown signature algorithm"
            raise Linzer::Error.new alg_error unless method

            Linzer.public_send(method, key_data[:material], keyid.to_s)
          end
        end

        include Parameters
        include Configuration
        include Key
      end
    end
  end
end
