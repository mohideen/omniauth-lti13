# frozen_string_literal: true

module OmniAuth
  module Lti13
    class Error < StandardError; end

    # Raised (and turned into a standard OmniAuth failure response by the
    # base OmniAuth::Strategy#call! rescue) when a launch or callback
    # arrives with an `iss` that doesn't match any configured platform.
    # Deliberately no fallback-to-default behavior here -- an unregistered
    # issuer must be rejected, not silently accepted.
    class UnregisteredPlatformError < Error
      def initialize(issuer)
        super("no registered LTI platform for issuer #{issuer.inspect}")
      end
    end

    # Raised when the login-initiation request's `client_id` is present but
    # doesn't match the resolved platform's configured client_id. `client_id`
    # is optional on the initiation request (RECOMMENDED by the IMS Security
    # Framework, for Platforms that register multiple clients under one
    # issuer), so this only fires when it's actually sent and wrong -- it's
    # never used to select the platform in the first place, only to catch a
    # mismatch against what issuer-based lookup already resolved.
    #
    # Deliberately generic: OmniAuth's `fail!(e.message, e)` puts this
    # message on the failure redirect (Avalon surfaces it in a query param),
    # so it must not embed our registered client_id or the caller's. Log
    # the specifics at the raise site instead, where they're useful for an
    # operator without being handed to whoever triggered the failure.
    class ClientIdMismatchError < Error
      def initialize
        super("login initiation client_id does not match the registered platform")
      end
    end

    # Raised when a login-initiation request is missing a parameter the IMS
    # OIDC third-party-initiated login spec requires (`login_hint`,
    # `target_link_uri`). Rejecting early here means a misbehaving Platform
    # gets a clear tool-side error instead of being silently redirected to
    # an authorization request that's already missing required data and
    # will only fail later, harder to diagnose, on the Platform's end.
    class InvalidLoginInitiationError < Error
      def initialize(missing_params)
        super("login initiation request missing required param(s): #{missing_params.join(", ")}")
      end
    end

    # Raised when the id_token's deployment_id claim doesn't match any of
    # the resolved platform's registered deployment_ids (or is missing).
    # iss and client_id are already covered by platform lookup + the base
    # class's own aud verification -- this closes the last leg (iss +
    # client_id + deployment_id together identify a registered deployment,
    # rather than collapsing them into one opaque key the way LTI 1.1's
    # oauth_consumer_key did).
    #
    # Deliberately generic (see ClientIdMismatchError above for why): does
    # not embed the issuer or the platform's registered deployment_ids.
    class DeploymentMismatchError < Error
      def initialize
        super("deployment_id is not registered for this platform")
      end
    end

    # Raised when the id_token's header specifies (or defaults to) a JWS
    # algorithm outside this gem's explicit allowlist -- including "none",
    # the classic unsigned-token forgery vector. Replaces
    # OmniAuth::Strategies::OpenIDConnect's own algorithm check, which is
    # opt-in (only runs at all if `client_signing_alg` is explicitly
    # configured) and checks against one configured value rather than an
    # allowlist.
    class DisallowedAlgorithmError < Error
      def initialize(algorithm, allowed)
        super("id_token signed with disallowed algorithm #{algorithm.inspect} (allowed: #{allowed.join(", ")})")
      end
    end

    # Raised for id_token claim checks (iss/aud/nonce/iat) that this gem
    # re-verifies itself rather than via
    # OpenIDConnect::ResponseObject::IdToken#verify! -- that method's exp
    # check has no clock-skew tolerance, so it can't be reused as-is (see
    # ExpiredTokenError) and reimplementing the rest alongside it keeps all
    # id_token claim validation in one auditable place.
    class InvalidIdTokenError < Error
      def initialize(reason)
        super("id_token failed validation: #{reason}")
      end
    end

    # Raised when the id_token is expired even after allowing for
    # `clock_skew` seconds of tolerance (ordinary drift between our clock
    # and the Platform's, not a security weakening -- a token past its
    # exp-plus-skew is still rejected).
    class ExpiredTokenError < Error
      def initialize(exp)
        super("id_token expired at #{exp.inspect} (beyond configured clock-skew tolerance)")
      end
    end

    # Raised when the id_token's optional `azp` (authorized party) claim is
    # present but doesn't match the client_id we expect. Per the OIDC Core
    # spec, azp only needs checking when present (it disambiguates the
    # audience when aud has multiple values); OmniAuth::Strategies::
    # OpenIDConnect doesn't check it at all.
    #
    # Deliberately generic (see ClientIdMismatchError above for why): does
    # not embed either the token's azp or our registered client_id.
    class InvalidAzpError < Error
      def initialize
        super("id_token azp does not match the expected client_id")
      end
    end

    # Raised when an issuer maps to more than one registered Platform (e.g.
    # Canvas Cloud's shared https://canvas.instructure.com issuer across
    # tenants) and the request doesn't supply a client_id to disambiguate.
    # client_id is optional on the login-initiation request in general, but
    # effectively required whenever a Platform's issuer is shared across
    # more than one of this tool's registrations -- guessing which one is
    # meant would be wrong far more often than it'd be convenient.
    class AmbiguousPlatformError < Error
      def initialize(issuer)
        super("issuer #{issuer.inspect} matches more than one registered platform; client_id is required to " \
              "disambiguate")
      end
    end
  end
end
