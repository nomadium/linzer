require "linzer"
require "logger"
require "yaml"

# Rack::Auth::Signature implements HTTP Message Signatures, as per RFC 9421.
#
# Initialize with the Rack application that you want protecting.
# A hash with options and a block can be passed to customize, enhance
# or disable security checks applied to incoming requests.
#
module Rack
  module Auth
    class Signature
      def initialize(app, options = {}, &block)
        @app = app
        @options = load_options(options)
        instance_eval(&block) if block
      end

      def call(env)
        @request = Rack::Request.new(env)

        if excluded? || allowed?
          @app.call(env)
        else
          response = options[:error_response].values
          Rack::Response.new(*response).finish
        end
      end

      private

      def excluded?
        return false if !request
        Array(options[:except]).include?(request.path_info)
      end

      def allowed?
        has_signature? && acceptable? && verifiable?
      end

      DEFAULT_OPTIONS = {
        no_older_than: 900,
        created_required: true,
        nonce_required:   false,
        alg_required:     false,
        tag_required:     false,
        expires_required: false,
        keyid_required:   false,
        known_keys:       {},
        covered_components: %w[@method @request-target @authority date],
        error_response: {body: [], status: 401, headers: {}}
      }

      private_constant :DEFAULT_OPTIONS

      attr_reader :request, :options

      def params
        @signature.parameters || {}
      end

      def logger
        @logger ||= request.logger || ::Logger.new($stderr)
      end

      def has_signature?
        @message = Linzer::Message.new(request)
        @signature = Linzer::Signature.build(@message.headers)
        request.env["rack.signature"] = @signature
        (@signature.to_h.keys & %w[signature signature-input]).size == 2
      rescue => ex
        logger.error ex.message
        false
      end

      def created?
        required = options[:created_required]
        if required
          params.key?("created") && Integer(params["created"])
        else
          !required
        end
      end

      def expires?
        required = options[:expires_required]
        if required
          params.key?("expires") && Integer(params["expires"]) > Time.now.to_i
        else
          !required
        end
      end

      def keyid?
        required = options[:keyid_required]
        required ? params.key?("keyid") : !required
      end

      def nonce?
        required = options[:nonce_required]
        required ? params.key?("nonce") : !required
      end

      def alg?
        required = options[:alg_required]
        required ? params.key?("alg") : !required
      end

      def tag?
        required = options[:tag_required]
        required ? params.key?("tag") : !required
      end

      def has_required_params?
        created? && expires? && keyid? && nonce? && alg? && tag?
      rescue => ex
        logger.error ex.message
        false
      end

      def has_required_components?
        components         = @signature.components || []
        covered_components = options[:covered_components]
        warning = "Insufficient coverage by signature. Consult S 7.2.1. in RFC"
        logger.warn warning if covered_components.empty?
        (covered_components || []).all? { |c| components.include?(c) }
      end

      def acceptable?
        has_required_params? && has_required_components?
      end

      def verifiable?
        verify_opts = {}

        warning = "Risk of signature replay! (Consult S 7.2.2. in RFC)"
        logger.warn warning unless options[:no_older_than]

        if options[:no_older_than]
          age = Integer(options[:no_older_than])
          verify_opts[:no_older_than] = age
        end

        Linzer.verify(key, @message, @signature, **verify_opts)
      rescue => ex
        logger.error ex.message
        false
      end

      def key
        build_key(params["keyid"] || :default)
      end

      def build_key(keyid)
        material = if keyid == :default
          options[:default_key]
        else
          key_data = options[:known_keys][keyid] || {}
          if !key_data.key?("key") && key_data.key?("path")
            key_data["key"] = IO.read(key_data["path"]) rescue nil
          end
          key_data
        end

        key_not_found = "Key not found. Signature cannot be verified."
        raise Linzer::Error.new key_not_found if !material || !material["key"]

        alg = @signature.parameters["alg"] || material["alg"] || :unknown
        instantiate_key(keyid, alg, material)
      end

      def instantiate_key(keyid, alg, material)
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

        Linzer.public_send(method, material["key"], keyid.to_s)
      end

      def load_options(options)
        DEFAULT_OPTIONS
          .merge(load_options_from_config_file(options))
          .merge(Hash(options)) || {}
      end

      def load_options_from_config_file(options)
        config_path = options[:config_path]
        YAML
          .safe_load_file(config_path)
          .transform_keys(&:to_sym)
      rescue
        {}
      end
    end
  end
end
