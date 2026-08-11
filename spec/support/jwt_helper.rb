# frozen_string_literal: true

# Builds signed id_tokens for specs, so callback-phase behavior can be
# tested against real (self-signed, in-memory) JWTs instead of stubbing
# decode_id_token -- exercising the actual signature-verification path
# omniauth_openid_connect provides.
module JwtHelper
  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  def jwk
    @jwk ||= JSON::JWK.new(rsa_key.public_key)
  end

  def build_id_token(claims, key: rsa_key, alg: :RS256)
    JSON::JWT.new(claims).sign(key, alg).to_s
  end
end
