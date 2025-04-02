require "linzer"
require "logger"

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
        @options = DEFAULT_OPTIONS.merge(Hash(options)) || {}
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
        keyid_required: false,
        covered_components: %w[@method @request-target @authority date],
        error_response: {body: [], status: 401, headers: {}}
      }

      private_constant :DEFAULT_OPTIONS

      attr_reader :request, :options

      def params
        @params ||= @signature.parameters || {}
      end

      def logger
        @logger ||= request.logger || ::Logger.new($stderr)
      end

      def has_signature?
        @message = Linzer::Message.new(request)
        @signature = Linzer::Signature.build(@message.headers)
        (@signature.to_h.keys & %w[signature signature-input]).size == 2
      rescue => ex
        logger.error ex.message
        false
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

      def has_required_params?
        return false if !params.key?("keyid") && options[:keyid_required]
        params.key?("created") && Integer(params["created"])
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

      def key
        build_key(params["keyid"] || :default)
      end

      def build_key(keyid)
        material = (keyid == :default) ? options[:default_key] : options[keyid]

        key_not_found = "Key not found. Signature cannot be verified."
        raise Linzer::Error.new key_not_found unless material

        alg = @signature.parameters["alg"] || material[:alg] || :unknown
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

        Linzer.public_send(method, material[:key], keyid.to_s)
      end
    end
  end
end
