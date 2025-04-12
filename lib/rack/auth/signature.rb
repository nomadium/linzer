require "linzer"
require "logger"
require_relative "signature/helpers"

# Rack::Auth::Signature implements HTTP Message Signatures, as per RFC 9421.
#
# Initialize with the Rack application that you want protecting.
# A hash with options and a block can be passed to customize, enhance
# or disable security checks applied to incoming requests.
#
module Rack
  module Auth
    class Signature
      include Helpers

      def initialize(app, options = {}, &block)
        @app = app
        @options = load_options(Hash(options))
        instance_eval(&block) if block
      end

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

      def excluded?
        return false if !request
        Array(options[:except]).include?(request.path_info)
      end

      def allowed?
        has_signature? && acceptable? && verifiable?
      end

      attr_reader :request, :options

      def params
        @signature.parameters || {}
      end

      def logger
        @logger ||= request.logger || ::Logger.new($stderr)
      end

      def has_signature?
        @signature = build_signature
        (@signature.to_h.keys & %w[signature signature-input]).size == 2
      rescue => ex
        logger.error ex.message
        false
      end

      def build_signature
        signature_opts = {}
        label = options[:signatures][:default_label]
        signature_opts[:label] = label if label

        @message = Linzer::Message.new(request)
        signature = Linzer::Signature.build(@message.headers, **signature_opts)
        request.env["rack.signature"] = signature
        signature
      end

      def has_required_params?
        created? && expires? && keyid? && nonce? && alg? && tag?
      rescue => ex
        logger.error ex.message
        false
      end

      def has_required_components?
        components         = @signature.components || []
        covered_components = options[:signatures][:covered_components]
        warning = "Insufficient coverage by signature. Consult S 7.2.1. in RFC"
        logger.warn warning if covered_components.empty?
        (covered_components || []).all? { |c| components.include?(c) }
      end

      def acceptable?
        has_required_params? && has_required_components?
      end

      def verifiable?
        verify_opts = build_and_check_verify_opts || {}
        Linzer.verify(key, @message, @signature, **verify_opts)
      rescue => ex
        logger.error ex.message
        false
      end

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
