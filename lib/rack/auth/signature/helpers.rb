# frozen_string_literal: true

require "yaml"

module Rack
  module Auth
    class Signature
      # Shared helpers for the Rack signature verification middleware.
      #
      # Organizes functionality into three sub-modules:
      # - {Parameters} — validates required signature parameters
      # - {Configuration} — loads and merges middleware options
      # - {Key} — resolves verification keys by keyid
      #
      # @api private
      module Helpers
        # Validates the presence of required signature parameters.
        #
        # Each method checks whether a specific parameter is required
        # (per configuration) and, if so, whether it is present and valid
        # in the current signature.
        #
        # @api private
        module Parameters
          private

          # Checks if the +created+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present and valid
          def created?
            !options[:signatures][:created_required] || !!Integer(params.fetch("created"))
          end

          # Checks if the +expires+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present and not yet expired
          def expires?
            return true if !options[:signatures][:expires_required]
            Integer(params.fetch("expires")) > Time.now.to_i
          end

          # Checks if the +keyid+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present
          def keyid?
            !options[:signatures][:keyid_required] || String(params.fetch("keyid"))
          end

          # Checks if the +nonce+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present
          def nonce?
            !options[:signatures][:nonce_required] || String(params.fetch("nonce"))
          end

          # Checks if the +alg+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present
          def alg?
            !options[:signatures][:alg_required] || String(params.fetch("alg"))
          end

          # Checks if the +tag+ parameter requirement is satisfied.
          # @return [Boolean] +true+ if not required or present
          def tag?
            !options[:signatures][:tag_required] || String(params.fetch("tag"))
          end
        end

        # Handles loading and merging of middleware configuration.
        #
        # Configuration can come from three sources (in order of precedence):
        # 1. Options passed directly to the middleware constructor
        # 2. A YAML configuration file (via +:config_path+)
        # 3. {DEFAULT_OPTIONS}
        #
        # @api private
        module Configuration
          # Returns the default covered components for signature verification.
          # @return [Array<String>] the default components from {Linzer::Options::DEFAULT}
          def default_covered_components
            Linzer::Options::DEFAULT[:covered_components]
          end
          module_function :default_covered_components

          # Default middleware configuration.
          #
          # @api private
          DEFAULT_OPTIONS = {
            signatures: {
              reject_older_than:  900,
              created_required:   true,
              nonce_required:     false,
              alg_required:       false,
              tag_required:       false,
              expires_required:   false,
              keyid_required:     false,
              covered_components:
                Linzer::FieldId
                  .serialize_components(default_covered_components),
              error_response:     {body: [], status: 401, headers: {}}
            },
            keys: {}
          }

          private_constant :DEFAULT_OPTIONS

          private

          # Loads and merges options from all sources.
          #
          # @param options [Hash] options passed to the middleware constructor
          # @return [Hash] the merged configuration
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

          # Loads configuration from a YAML file.
          #
          # @param options [Hash] options containing +:config_path+
          # @return [Hash] parsed configuration, or empty hash if unavailable
          def load_options_from_config_file(options)
            config_path = options[:config_path]
            YAML.safe_load_file(config_path, symbolize_names: true)
          rescue
            {}
          end
        end

        # Resolves verification keys from the middleware configuration.
        #
        # Keys can be configured inline (with +:material+) or via file path
        # (with +:path+). When a +keyid+ is present in the signature, the
        # corresponding key is looked up in the +:keys+ hash. If not found,
        # the +:default_key+ is used as fallback.
        #
        # @api private
        module Key
          private

          # Returns the verification key for the current signature.
          # @return [Linzer::Key] the resolved key
          # @raise [Linzer::Error] if no key can be found
          def key
            build_key(params["keyid"])
          end

          # Builds a key instance from configuration.
          #
          # @param keyid [String, nil] the key identifier from the signature
          # @return [Linzer::Key] the resolved key
          # @raise [Linzer::Error] if no matching key configuration is found
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

          # Instantiates the appropriate key class for the given algorithm.
          #
          # @param keyid [String, Symbol] the key identifier
          # @param alg [String, Symbol] the algorithm identifier
          #   (e.g. +"ed25519"+, +"rsa-pss-sha512"+)
          # @param key_data [Hash] key configuration with +:material+
          # @return [Linzer::Key] the instantiated key
          # @raise [Linzer::Error] if the algorithm is unsupported
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
