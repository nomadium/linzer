# frozen_string_literal: true

require "linzer"
require "logger"
require_relative "signature/helpers"

module Rack
  module Auth
    # Rack middleware for HTTP Message Signature verification (RFC 9421).
    #
    # This middleware verifies that incoming requests have valid HTTP signatures.
    # Requests without valid signatures are rejected with a 401 Unauthorized response.
    #
    # @example Basic usage in config.ru
    #   require "linzer"
    #
    #   use Rack::Auth::Signature,
    #     except: "/health",
    #     default_key: {
    #       material: File.read("public_key.pem"),
    #       alg: "ed25519"
    #     }
    #
    #   run MyApp
    #
    # @example With configuration file
    #   use Rack::Auth::Signature,
    #     except: ["/login", "/health"],
    #     config_path: "config/http-signatures.yml"
    #
    # @example In a Rails application (config/application.rb)
    #   config.middleware.use Rack::Auth::Signature,
    #     except: "/login",
    #     config_path: "config/http-signatures.yml"
    #
    # @example With a block for custom configuration
    #   use Rack::Auth::Signature do
    #     # Custom configuration via instance_eval
    #   end
    #
    # Configuration file format (YAML):
    #
    #   signatures:
    #     reject_older_than: 900        # Reject signatures older than 15 minutes
    #     created_required: true        # Require 'created' parameter
    #     keyid_required: false         # Require 'keyid' parameter
    #     covered_components:           # Required components in signature
    #       - "@method"
    #       - "@request-target"
    #       - "date"
    #   keys:
    #     my-key-id:
    #       alg: ed25519
    #       material: |                 # Inline PEM
    #         -----BEGIN PUBLIC KEY-----
    #         ...
    #         -----END PUBLIC KEY-----
    #     other-key:
    #       alg: rsa-pss-sha512
    #       path: keys/public.pem       # Or path to key file
    #
    # @see https://www.rfc-editor.org/rfc/rfc9421.html RFC 9421
    # @see Helpers::Configuration For configuration options
    # @see Helpers::Key For key lookup behavior
    class Signature
      include Helpers

      # Creates a new signature verification middleware.
      #
      # @param app [#call] The Rack application to protect
      # @param options [Hash] Configuration options
      # @option options [String, Array<String>] :except Paths to exclude from
      #   signature verification (e.g., "/login", "/health")
      # @option options [String] :config_path Path to YAML configuration file
      # @option options [Hash] :default_key Default key configuration when
      #   keyid is not present or not found in keys hash
      # @option options [Hash] :keys Hash of key configurations keyed by keyid
      # @option options [Hash] :signatures Signature verification options
      #
      # @yield Optional block for additional configuration via instance_eval
      def initialize(app, options = {}, &block)
        @app = app
        @options = load_options(Hash(options))
        instance_eval(&block) if block
      end

      # Processes an incoming request.
      #
      # If the request path is excluded or the signature is valid, the request
      # is passed to the wrapped application. Otherwise, returns a 401 response.
      #
      # On successful verification, the signature is stored in `env["rack.signature"]`
      # for use by the application.
      #
      # @param env [Hash] The Rack environment
      # @return [Array] Rack response tuple [status, headers, body]
      def call(env)
        @request = Rack::Request.new(env)

        if excluded? || allowed?
          @app.call(env)
        else
          response = options[:signatures][:error_response].values
          Rack::Response.new(*response).finish
        end
      end

      private

      # Checks if the current request path is excluded from verification.
      def excluded?
        return false if !request
        Array(options[:except]).include?(request.path_info)
      end

      # Checks if the request should be allowed (has valid signature).
      def allowed?
        has_signature? && acceptable? && verifiable?
      end

      attr_reader :request, :options

      # Returns the signature parameters.
      def params
        @signature.parameters || {}
      end

      # Returns the logger instance.
      def logger
        @logger ||= request.logger || ::Logger.new($stderr)
      end

      # Checks if the request has signature headers.
      def has_signature?
        @signature = build_signature
        (@signature.to_h.keys & %w[signature signature-input]).size == 2
      rescue => ex
        logger.error ex.message
        false
      end

      # Builds a Signature object from request headers.
      def build_signature
        signature_opts = {}
        label = options[:signatures][:default_label]
        signature_opts[:label] = label if label

        @message = Linzer::Message.new(request)
        signature_headers = {}
        %w[signature-input signature].each do |name|
          value = @message.header(name)
          signature_headers[name] = value if value
        end
        signature = Linzer::Signature.build(signature_headers, **signature_opts)
        request.env["rack.signature"] = signature
        signature
      end

      # Checks if required signature parameters are present.
      def has_required_params?
        created? && expires? && keyid? && nonce? && alg? && tag?
      rescue => ex
        logger.error ex.message
        false
      end

      # Checks if required components are covered by the signature.
      def has_required_components?
        components         = @signature.serialized_components || []
        covered_components = options[:signatures][:covered_components]
        warning = "Insufficient coverage by signature. Consult S 7.2.1. in RFC"
        logger.warn warning if covered_components.empty?
        (covered_components || []).all? { |c| components.include?(c) }
      end

      # Checks if the signature meets all requirements.
      def acceptable?
        has_required_params? && has_required_components?
      end

      # Verifies the signature cryptographically.
      def verifiable?
        verify_opts = build_and_check_verify_opts || {}
        Linzer.verify(key, @message, @signature, **verify_opts)
      rescue => ex
        logger.error ex.message
        false
      end

      # Builds verification options and logs warnings for security issues.
      def build_and_check_verify_opts
        verify_opts = {}
        reject_older = options[:signatures][:reject_older_than]
        warning = "Risk of signature replay! (Consult S 7.2.2. in RFC)"
        logger.warn warning unless reject_older

        if reject_older
          age = Integer(reject_older)
          verify_opts[:no_older_than] = age
        end

        verify_opts
      end
    end
  end
end
