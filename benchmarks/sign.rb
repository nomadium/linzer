require "benchmark_driver"
require "openssl"
require "linzer"
require "linzer/ml_dsa"

BENCH_ALGS = %i[
  ed25519
  ecdsa_p256_sha256
  ecdsa_p384_sha384
  rsa_v1_5_sha256
  rsa_pss_sha512
  hmac_sha256
  jws_ed25519
  ml_dsa_44_openssl
  ml_dsa_44_ml_dsa
]

puts "Linzer.sign! benchmark — supported algorithms"
puts `git show HEAD | head -1 | cut -b 1-15`
puts "Ruby #{RUBY_VERSION} / #{RUBY_PLATFORM}"
puts "OpenSSL #{OpenSSL::VERSION}"
puts Time.now.utc

BENCH_ALGS.each do |alg|
  next if alg == :rsa_pss_sha512 && RUBY_VERSION < "3.1.0"
  next if alg == :ml_dsa_44_openssl && !Linzer::MLDSA.openssl_supported?("ml-dsa-44")
  Benchmark.driver do |x|
    x.prelude <<~RUBY
      require "bundler/setup"
      require "linzer"
      require "linzer/jws"
      require "linzer/ml_dsa"

      def generate_linzer_key(alg)
        case alg
        when :ed25519, :ecdsa_p256_sha256, :ecdsa_p384_sha384, :hmac_sha256
          Linzer.public_send(:"generate_#{alg}_key", "bench-#{alg}")
        when :rsa_v1_5_sha256, :rsa_pss_sha512
          Linzer.public_send(:"generate_#{alg}_key", 2048, "bench-#{alg}")
        when :jws_ed25519
          Linzer.generate_jws_key(algorithm: "EdDSA")
        when :ml_dsa_44_openssl
          Linzer.generate_ml_dsa_44_key("bench-#{alg}", backend: :openssl)
        when :ml_dsa_44_ml_dsa
          Linzer.generate_ml_dsa_44_key("bench-#{alg}", backend: :ml_dsa)
        else
          raise ArgumentError, "Unknown algorithm!"
        end
      end

      key = generate_linzer_key(:"#{alg}")
      uri        = URI("https://example.com/api/resource")
      components = %w[@method @path @authority content-type]
    RUBY

    puts "\n#{alg}:\n#{"#" * 70}\n\n"

    x.report "[#{alg}] sign!", %{
      request = Net::HTTP::Post.new(uri)
      request["content-type"] = "application/json"
      request.body = '{"hello":"world"}'
      Linzer.sign!(request, key: key, components: components)
    }
  end
end
