# frozen_string_literal: true

require "open3"
require "linzer/ml_dsa"
require_relative "fixtures/httpsig_pq_vectors"

ml_dsa_vectors = Linzer::Test::HTTPSIG_PQ_VECTORS.to_h do |vector|
  [vector.fetch(:parameter_set), vector]
end.freeze

RSpec.describe "ML-DSA HTTP Message Signatures" do
  let(:uri) { URI("https://example.com/foo?param=Value&Pet=dog") }
  let(:request) do
    Net::HTTP::Get.new(uri).tap do |req|
      req["host"] = "example.com"
      req["date"] = "Mon, 06 Jul 2026 20:00:00 GMT"
    end
  end
  let(:message) { Linzer::Message.new(request) }
  let(:components) { %w[@method @target-uri host date] }

  ml_dsa_vectors.each do |parameter_set, vector|
    context "with ML-DSA-#{parameter_set}" do
      # :auto exercises whatever this host actually selects by default
      # (OpenSSLKey when available, GemKey otherwise); :ml_dsa is forced
      # explicitly so GemKey stays exercised by CI even on hosts where
      # :auto would otherwise always resolve to :openssl.
      %i[auto ml_dsa].each do |backend|
        context "with backend: #{backend.inspect}" do
          let(:algorithm) { "ml-dsa-#{parameter_set}" }
          let(:key_id) { "test-key-mldsa#{parameter_set}-#{backend}" }
          let(:key) { Linzer.public_send("generate_ml_dsa_#{parameter_set}_key", key_id, backend: backend) }
          let(:public_key) do
            Linzer.public_send(
              "new_ml_dsa_#{parameter_set}_key",
              Base64.strict_decode64(vector.fetch(:public_key)),
              key_id,
              backend: backend
            )
          end
          let(:raw_signature) { Base64.strict_decode64(vector.fetch(:signature)) }
          let(:published_signature) do
            Linzer::Signature.build({
              "signature-input" => vector.fetch(:signature_input),
              "signature" => "sig1=:#{vector.fetch(:signature)}:"
            })
          end

          it "verifies the published C2SP signature" do
            signature_base = Linzer.signature_base(
              message,
              published_signature.serialized_components,
              published_signature.parameters
            )

            expect(signature_base).to eq(vector.fetch(:signature_base))
            expect(Linzer.verify(public_key, message, published_signature)).to eq(true)
          end

          it "signs and verifies the unhashed RFC 9421 signature base" do
            signature = Linzer.sign(
              key,
              message,
              components,
              created: 1783368000,
              keyid: key_id,
              alg: algorithm
            )

            expected_input =
              %(sig1=("@method" "@target-uri" "host" "date");created=1783368000;) +
              %(keyid="#{key_id}";alg="#{algorithm}")

            expect(signature.to_h["signature-input"]).to eq(expected_input)
            expected_size = Base64.strict_decode64(vector.fetch(:signature)).bytesize
            expect(signature.bytes.bytesize).to eq(expected_size)
            expect(Linzer.verify(key, message, signature)).to eq(true)
          end

          it "rejects the C2SP modified-component case" do
            modified_request = Net::HTTP::Get.new(uri).tap do |req|
              req["host"] = "example.com"
              req["date"] = "Mon, 06 Jul 2026 20:00:01 GMT"
            end

            expect {
              Linzer.verify(public_key, Linzer::Message.new(modified_request), published_signature)
            }.to raise_error(Linzer::VerifyError, /Invalid signature/)
          end

          it "rejects the C2SP missing-covered-component case" do
            modified_base = vector.fetch(:signature_base).sub(
              %("@target-uri": https://example.com/foo?param=Value&Pet=dog\n),
              ""
            )

            expect(public_key.verify(raw_signature, modified_base)).to eq(false)
          end

          it "rejects both C2SP algorithm-substitution cases" do
            (ml_dsa_vectors.keys - [parameter_set]).each do |substituted_parameter_set|
              headers = published_signature.to_h.transform_values(&:dup)
              headers["signature-input"].sub!(
                algorithm,
                "ml-dsa-#{substituted_parameter_set}"
              )

              expect do
                Linzer.verify(public_key, message, Linzer::Signature.build(headers))
              end.to raise_error(Linzer::VerifyError, /does not match key algorithm/)
            end
          end

          it "rejects the C2SP wrong-key cases" do
            ml_dsa_vectors.each do |wrong_parameter_set, wrong_vector|
              next if wrong_parameter_set == parameter_set

              wrong_key = Linzer.public_send(
                "new_ml_dsa_#{wrong_parameter_set}_key",
                Base64.strict_decode64(wrong_vector.fetch(:public_key)),
                nil,
                backend: backend
              )
              expect(wrong_key.verify(raw_signature, vector.fetch(:signature_base))).to eq(false)
            end
          end

          it "rejects the C2SP signature bit-flip case" do
            flipped_signature = raw_signature.dup
            flipped_signature.setbyte(0, flipped_signature.getbyte(0) ^ 1)

            expect(public_key.verify(flipped_signature, vector.fetch(:signature_base))).to eq(false)
          end

          it "rejects the C2SP truncated-signature case" do
            truncated_signature = raw_signature.byteslice(0...-1)

            expect(public_key.verify(truncated_signature, vector.fetch(:signature_base))).to eq(false)
          end

          it "rejects the C2SP extended-signature case" do
            expect(public_key.verify(raw_signature + "\x00", vector.fetch(:signature_base))).to eq(false)
          end

          it "rejects the C2SP non-empty-context case" do
            skip "no non-empty-context signing/verification API on the OpenSSL backend" unless
              public_key.backend == :ml_dsa

            expect(
              public_key.material.verify(
                vector.fetch(:signature_base),
                raw_signature,
                context: "not-empty"
              )
            ).to eq(false)
          end

          it "rejects the C2SP prehashed-message case" do
            digest = OpenSSL::Digest::SHA256.digest(vector.fetch(:signature_base))

            expect(public_key.verify(raw_signature, digest)).to eq(false)
          end
        end
      end
    end
  end

  context "ML-DSA gem-backend error handling when unavailable" do
    # Both scenarios need a genuinely fresh Ruby process: RSpec's loading
    # phase already requires "linzer/ml_dsa" (via ml_dsa_spec.rb
    # and ml_dsa_cross_backend_spec.rb) before any example runs, so
    # Linzer::MLDSA::GemKey is already a defined constant, and the file's
    # own top-level `require "ml_dsa"` has already succeeded, process-wide,
    # by the time this spec's examples run. Neither condition can be
    # reproduced again in the same process.
    def run_in_fresh_process(script)
      Open3.capture2e("ruby", "-Ilib", "-e", script)
    end

    it "raises a clear error for backend: :ml_dsa when linzer/ml_dsa was never required" do
      script = <<~'RUBY'
        require "linzer"
        begin
          Linzer.generate_ml_dsa_44_key(backend: :ml_dsa)
          exit 1
        rescue Linzer::Error => e
          puts e.message
          exit 0
        rescue => e
          puts "WRONG ERROR CLASS: #{e.class}: #{e.message}"
          exit 2
        end
      RUBY

      output, status = run_in_fresh_process(script)

      expect(status).to be_success, "expected a clean exit, got:\n#{output}"
      expect(output).to include('require "linzer/ml_dsa" first')
    end

    it "raises a clear error from gem_key.rb's own require when the ml_dsa gem itself is unavailable" do
      script = <<~'RUBY'
        module Kernel
          alias_method :__original_require_for_test, :require
          def require(name)
            raise LoadError, "cannot load such file -- ml_dsa" if name == "ml_dsa"
            __original_require_for_test(name)
          end
        end

        require "linzer"
        begin
          require "linzer/ml_dsa"
          exit 1
        rescue Linzer::Error => e
          puts e.message
          exit 0
        rescue => e
          puts "WRONG ERROR CLASS: #{e.class}: #{e.message}"
          exit 2
        end
      RUBY

      output, status = run_in_fresh_process(script)

      expect(status).to be_success, "expected a clean exit, got:\n#{output}"
      expect(output).to include("ml_dsa gem must be installed")
    end
  end
end
