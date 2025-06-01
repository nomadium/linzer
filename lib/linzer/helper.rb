# frozen_string_literal: true

module Linzer
  module Helper
    def sign!(request_or_response, **args)
      message = Message.new(request_or_response)
      options = {}

      label = args[:label]
      options[:label] = label if label
      options.merge!(args.fetch(:params, {}))

      key = args.fetch(:key)
      signature = Linzer::Signer.sign(key, message, args.fetch(:components), options)
      message.attach!(signature)
    end

    def verify!(request_or_response, key: nil, no_older_than: 900)
      message = Message.new(request_or_response)
      signature_headers = {}
      %w[signature-input signature].each do |name|
        value = message.header(name)
        signature_headers[name] = value if value
      end
      signature = Signature.build(signature_headers)
      keyid = signature.parameters["keyid"]
      raise Linzer::Error, "key not found" if !key && !keyid
      verify_key = block_given? ? (yield keyid) : key
      Linzer.verify(verify_key, message, signature, no_older_than: no_older_than)
    end
  end
end
