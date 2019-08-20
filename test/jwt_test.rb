require "test_helper"
module Virgil
  module Jwt
    class JwtTest < Minitest::Test
      include Virgil::Crypto

      def setup
        @crypto = VirgilCrypto.new
        @api_priv_key = @crypto.import_private_key(Bytes.from_base64(api_data['api_priv_key_base64']))
        @app_id = api_data['app_id']
        @api_public_key_id = api_data['api_public_key']

      end
      def test_that_it_has_a_version_number
        refute_nil Virgil::Jwt::VERSION
      end

      def test_it_does_something_useful
        assert true
      end

      # STC-28
      def test_from_should_initialize_valid_token
        jwt = Jwt.from(compatibility_data['STC-28.jwt'])
        assert_equal(compatibility_data['STC-28.jwt_identity'], jwt.body_content.identity)
        assert_equal(compatibility_data['STC-28.jwt_app_id'], jwt.body_content.app_id)
        assert_equal(compatibility_data['STC-28.jw_issuer'], jwt.body_content.issuer)

        assert_equal(compatibility_data['STC-28.jwt_subject'], jwt.body_content.subject)
        assert_equal(JSON.parse(compatibility_data['STC-28.jwt_additional_data']), jwt.body_content.additional_data)

        assert_equal(compatibility_data['STC-28.jwt_expires_at'].to_i, jwt.body_content.expires_at.to_i)

        assert_equal(compatibility_data['STC-28.jwt_issued_at'].to_i, jwt.body_content.issued_at.to_i)

        assert_equal(compatibility_data['STC-28.jwt_algorithm'], jwt.header_content.algorithm)

        assert_equal(compatibility_data['STC-28.jwt_api_key_id'], jwt.header_content.key_id)

        assert_equal(compatibility_data['STC-28.jwt_content_type'], jwt.header_content.content_type)

        assert_equal(compatibility_data['STC-28.jwt_type'], jwt.header_content.type)

        assert_equal(compatibility_data['STC-28.jwt_signature_base64'],
                     jwt.signature_data.to_string(VirgilStringEncoding::BASE64))
      end

      # STC-29
      def test_from_should_initialize_valid_unexpired_token
        jwt = Jwt.from(compatibility_data['STC-29.jwt'])
        assert_equal(compatibility_data['STC-29.jwt_identity'], jwt.body_content.identity)
        assert_equal(compatibility_data['STC-29.jwt_app_id'], jwt.body_content.app_id)
        assert_equal(compatibility_data['STC-29.jw_issuer'], jwt.body_content.issuer)

        assert_equal(compatibility_data['STC-29.jwt_subject'], jwt.body_content.subject)
        assert_equal(JSON.parse(compatibility_data['STC-29.jwt_additional_data']), jwt.body_content.additional_data)

        assert_equal(compatibility_data['STC-29.jwt_expires_at'].to_i, jwt.body_content.expires_at.to_i)

        assert_equal(compatibility_data['STC-29.jwt_issued_at'].to_i, jwt.body_content.issued_at.to_i)

        assert_equal(compatibility_data['STC-29.jwt_algorithm'], jwt.header_content.algorithm)

        assert_equal(compatibility_data['STC-29.jwt_api_key_id'], jwt.header_content.key_id)

        assert_equal(compatibility_data['STC-29.jwt_content_type'], jwt.header_content.content_type)

        assert_equal(compatibility_data['STC-29.jwt_type'], jwt.header_content.type)

        assert_equal(compatibility_data['STC-29.jwt_signature_base64'],
                     jwt.signature_data.to_string(VirgilStringEncoding::BASE64))
        assert_equal(false, jwt.expired?)
        assert_equal(compatibility_data['STC-29.jwt'], jwt.to_s)
      end


      # STC-24
      def test_CallbackJwtProvider_always_returns_new_token

        jwt_generator = JwtGenerator.new(app_id: @app_id,
                                         api_key: @api_priv_key,
                                         api_public_key_id: @api_public_key_id,
                                         life_time: 10,
                                         access_token_signer: VirgilAccessTokenSigner.new
                                         )
        obtain_token_proc = proc { jwt_generator.generate_token('my_token_identity').to_s }
        provider = CallbackJwtProvider.new(obtain_token_proc)
        ctx = TokenContext.new(operation: 'TestOperation', identity:'my_token_identity', service: 'Test service')

        # returns new token
        token = provider.get_token(ctx)
        assert token
        assert_equal(obtain_token_proc, provider.obtain_access_token_proc)

        # returns new token
        token2 = provider.get_token(ctx)
        assert token2
        assert(token != token2)
      end


      # STC-38
      def test_CachingJwtProvider_returns_new_token_only_if_expired
        jwt_generator = JwtGenerator.new(app_id: @app_id,
                                         api_key: @api_priv_key,
                                         api_public_key_id: @api_public_key_id,
                                         life_time: 1,
                                         access_token_signer: VirgilAccessTokenSigner.new()
        )

        obtain_token_proc = proc { jwt_generator.generate_token('my_token_identity').to_s }
        provider = CachingJwtProvider.new(obtain_token_proc)
        ctx = TokenContext.new(operation: 'TestOperation', identity:'my_token_identity', service: 'Test service')

        # returns new token
        token = provider.get_token(ctx)
        assert token
        assert_equal(obtain_token_proc, provider.renew_access_token_proc)

        token2 = provider.get_token(ctx)
        assert token2
        assert_equal(token, token2)

        sleep 60
        # returns new token
        token3 = provider.get_token(ctx)
        assert token3
        assert(token != token3)
      end


      # STC-37
      def test_ConstAccessTokenProvider_always_returns_the_same_token
        jwt_generator = JwtGenerator.new(app_id: @app_id,
                                         api_key: @api_priv_key,
                                         api_public_key_id: @api_public_key_id,
                                         life_time: 1,
                                         access_token_signer: VirgilAccessTokenSigner.new()
        )
        token = jwt_generator.generate_token('my_token_identity')
        provider = ConstAccessTokenProvider.new(token)
        ctx = TokenContext.new(operation: 'TestOperation', identity:'my_token_identity', service: 'Test service')


        # returns new token
        token1 = provider.get_token(ctx)
        assert token1
        assert_equal(token, token1)

        sleep 60

        # returns new token
        token2 = provider.get_token(ctx)
        assert token2
        assert_equal(token, token2)
      end

      # STC-39
      def test_CachingJwtProvider_is_thread_safe
        jwt_generator = JwtGenerator.new(app_id: @app_id,
                                         api_key: @api_priv_key,
                                         api_public_key_id: @api_public_key_id,
                                         life_time: 1,
                                         access_token_signer: VirgilAccessTokenSigner.new())

        obtain_token_proc = proc { jwt_generator.generate_token('my_token_identity').to_s }
        provider = CachingJwtProvider.new(obtain_token_proc)
        ctx = TokenContext.new(operation: 'TestOperation', identity:'my_token_identity', service: 'Test service')
        token_from_a = nil
        token_from_b = nil
        thread_a = Thread.new {
          token_from_a = provider.get_token(ctx)
        }
        thread_b = Thread.new {
          token_from_b = provider.get_token(ctx)
        }
        thread_a.join
        thread_b.join

       assert_equal(token_from_a.to_s, token_from_b.to_s)
      end

      def test_JwtVerifier_Should_VerifyImportedJwt
        api_pub_key = @crypto.extract_public_key(@api_priv_key)
        jwt_generator = JwtGenerator.new(app_id: @app_id,
                                         api_key: @api_priv_key,
                                         api_public_key_id: @api_public_key_id,
                                         life_time: 1,
                                         access_token_signer: VirgilAccessTokenSigner.new()
        )
        token = jwt_generator.generate_token('my_token_identity')

        verifier = JwtVerifier.new(access_token_signer: VirgilAccessTokenSigner.new,
                                   api_public_key: api_pub_key,
                                   api_public_key_id: @api_public_key_id)

        assert verifier.verify_token(token)
      end

      def compatibility_data
        @compatibility_data ||= decode_data(TestData.compatibility_data)
      end

      def api_data
        @api_data ||= decode_data(TestData.api_data)
      end
      def decode_data(data)
        case data
        when Hash
          data.each_with_object({}) {|(k, v), acc| acc[k] = decode_data(v)}
        when Array
          data.map {|v| decode_data(v)}
        # when String
          # Bytes.from_base64(data)
        else
          data
        end
      end
    end
  end
end
