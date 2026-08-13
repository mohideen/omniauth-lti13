# frozen_string_literal: true

require "omniauth_openid_connect"

module OmniAuth
  module Strategies
    # LTI 1.3 Core (launch/auth) as an OmniAuth strategy, built on top of
    # OmniAuth::Strategies::OpenIDConnect rather than reimplementing OIDC/JWT
    # handling. LTI Advantage (Deep Linking, AGS, NRPS) is out of scope.
    #
    # Named `Lti13`, not `Lti`, so it doesn't collide with the constant used
    # by the LTI 1.1 `omniauth-lti` gem -- the two can be loaded side by
    # side. `option :name` is what OmniAuth actually uses to pick the URL
    # path a strategy answers on, independent of the class name, so it's set
    # explicitly to "lti" here to match Avalon's `:lti` provider key.
    class Lti13 < OmniAuth::Strategies::OpenIDConnect
      option :name, "lti"

      # Registered Platforms this Avalon instance trusts, as an Array of
      # Hashes (or OmniAuth::Lti13::Platform instances) -- see the README
      # for the schema. A single instance may serve multiple LMS
      # deployments, so `client_options`/`issuer` can't be static
      # strategy-wide config; they're resolved per-request in setup_phase
      # below, keyed on the incoming `iss` and, when more than one
      # registration shares an issuer (e.g. Canvas Cloud's shared
      # https://canvas.instructure.com issuer across tenants), `client_id`.
      option :platforms, []

      # LTI 1.3 Core's launch flow is OIDC's implicit-style id_token flow,
      # not the authorization-code flow OmniAuth::Strategies::OpenIDConnect
      # defaults to -- there's no token endpoint round-trip. response_mode
      # is form_post per the IMS Security Framework (the Platform POSTs the
      # id_token back rather than appending it to a redirect fragment).
      option :response_type, "id_token"
      option :response_mode, "form_post"

      # login_hint and lti_message_hint are IMS-mandated round-trips: the
      # Platform sends them on the login-initiation request and expects them
      # echoed back unchanged on the authentication request. target_link_uri
      # is threaded through the same way, per this gem's own contract with
      # Avalon (see lti-gem-prompt.md). login_hint is technically already
      # handled unconditionally by the base class's authorize_uri -- listed
      # here too so the full set required by the flow is visible in one
      # place, since allow_authorize_params won't clobber an already-set key.
      #
      # client_id and deployment_id, also present on the login-initiation
      # request, are deliberately NOT in this list: they're read for
      # validation (see setup_phase) rather than forwarded, since letting an
      # unauthenticated request param overwrite the client_id our platform
      # lookup already resolved would defeat the point of that lookup.
      option :allow_authorize_params, %i[login_hint lti_message_hint target_link_uri]

      # Clock-skew tolerance (seconds) for id_token exp/iat validation --
      # ordinary drift between our clock and the Platform's shouldn't reject
      # an otherwise-valid launch. Configurable since deployments may want
      # to tune it; the algorithm allowlist below isn't, since the IMS
      # Security Framework mandates RS256 specifically.
      option :clock_skew, 60

      # IMS Security Framework 1.0 Section 5 mandates RS256 for LTI 1.3
      # JWKS-verified id_tokens. Rejecting everything else here -- including
      # "none", the classic unsigned-token forgery vector -- replaces
      # OmniAuth::Strategies::OpenIDConnect's own algorithm check, which is
      # opt-in (only runs if `client_signing_alg` is explicitly configured,
      # which this gem doesn't do) and checks against one configured value
      # rather than an allowlist.
      ALLOWED_ALGORITHMS = %i[RS256].freeze

      REQUIRED_INITIATION_PARAMS = %w[login_hint target_link_uri].freeze

      # The Platform resolved for the current request by setup_phase.
      attr_reader :current_platform

      # Built once, when the middleware is constructed, rather than lazily
      # via the more usual `@ivar ||=` memoized-reader pattern: OmniAuth's
      # Strategy#call does `dup.call!(env)`, handing every request a fresh
      # duped instance, so a `||=` inside a per-request method (e.g.
      # setup_phase) would never actually survive across requests -- it'd
      # rebuild the registry (and revalidate every configured Platform's
      # attributes) on every single launch and callback. Building it here
      # instead means it's computed once and carried into every dup via
      # Ruby's normal shallow ivar copy.
      def initialize(app, *args, &block)
        super
        @platform_registry = OmniAuth::Lti13::PlatformRegistry.new(options.platforms)
      end

      # Runs before both request_phase and callback_phase. Selects
      # `client_options`/`issuer` for this request based on the incoming
      # `iss` (and `client_id`, when needed to disambiguate), looked up
      # against the registered `:platforms` list. An unregistered (or
      # ambiguous) issuer raises rather than falling back to a default; the
      # raise propagates out through OmniAuth::Strategy#call!'s own rescue,
      # which turns it into a standard OmniAuth failure response.
      def setup_phase
        issuer = current_iss
        client_id = current_client_id

        unless on_request_path?
          # One-time-use, mirroring omniauth.state/omniauth.nonce: this
          # login attempt is finishing (successfully or not) either way.
          session.delete("omniauth.lti13.iss")
          session.delete("omniauth.lti13.client_id")
        end

        platform = platform_registry.find(issuer: issuer, client_id: client_id)
        raise OmniAuth::Lti13::UnregisteredPlatformError, issuer unless platform

        apply_platform!(platform)
      end

      private

      attr_reader :platform_registry

      # Overrides OmniAuth::Strategies::OpenIDConnect#request_phase to
      # validate the login-initiation request itself (required params
      # present, client_id consistent) and stash the resolved issuer and
      # client_id in the session for the callback leg to find, before
      # delegating to the base class's actual redirect-building logic.
      # These are request-phase-only concerns, so they belong here rather
      # than in setup_phase (which runs for both phases and should only do
      # the platform resolution both legs genuinely share).
      def request_phase
        validate_login_initiation!(current_platform)
        session["omniauth.lti13.iss"] = current_platform.issuer
        session["omniauth.lti13.client_id"] = current_platform.client_id
        super
      end

      # Overrides OmniAuth::Strategies::OpenIDConnect#id_token_callback_phase
      # (the callback path taken when response_type is "id_token", which is
      # always, here; private in the base class too). The base
      # implementation builds a bare-bones AuthHash (uid/name/email only);
      # this builds the full LTI auth_hash contract instead, and validates
      # deployment_id before doing so. decode_id_token re-verifies
      # iss/aud/nonce/signature -- already done once by verify_id_token!
      # earlier in callback_phase, but it's a cheap decode and keeping this
      # method self-contained (rather than threading the already-decoded
      # token through) matches the base class's own structure.
      def id_token_callback_phase
        claims = decode_id_token(params["id_token"]).raw_attributes
        validate_deployment!(claims)

        env["omniauth.auth"] = build_auth_hash(claims)
        call_app!
      end

      # Overrides OmniAuth::Strategies::OpenIDConnect's own algorithm check
      # (also private, also called from decode_id_token), which only runs
      # when `client_signing_alg` is configured and then checks against a
      # single value. This runs unconditionally against an allowlist.
      def validate_client_algorithm!(algorithm)
        return if ALLOWED_ALGORITHMS.include?(algorithm)

        raise OmniAuth::Lti13::DisallowedAlgorithmError.new(algorithm, ALLOWED_ALGORITHMS)
      end

      # Overrides OmniAuth::Strategies::OpenIDConnect#decode_id_token to add
      # one retry, with a forced JWKS re-fetch, when the key referenced by
      # the token can't be found in our current JWKS. The base method's own
      # KidNotFound handling only retries locally (trying each key already
      # in hand, for tokens with no kid) and re-raises immediately whenever
      # a kid IS present but unmatched -- it never re-fetches. Without this,
      # a Platform that rotates its signing key would 401 every launch
      # until whatever fetched our in-memory JWKS happened to restart.
      def decode_id_token(id_token)
        super
      rescue JSON::JWK::Set::KidNotFound
        @public_key = nil
        @fetch_key = nil
        super
      end

      # Overrides OmniAuth::Strategies::OpenIDConnect#verify_id_token!
      # entirely rather than calling super: the base implementation
      # (OpenIDConnect::ResponseObject::IdToken#verify!) checks exp with no
      # clock-skew tolerance, so a token just past nominal expiry would be
      # rejected by that check before this method ever got a chance to
      # apply its own, more lenient one -- there's no way to layer skew
      # tolerance on top of an already-stricter check via super. Since
      # iss/aud/nonce need reimplementing anyway to keep all id_token claim
      # validation in one auditable place, azp (which the base doesn't
      # check at all) is added alongside them here too.
      def verify_id_token!(id_token)
        return unless id_token

        validate_claims!(decode_id_token(id_token))
      end

      def validate_claims!(decoded)
        skew = options.clock_skew.to_i
        now = Time.now.to_i
        # Deliberately session-only, never params["nonce"]: the LTI 1.3
        # Authentication Response carries only id_token and state (per the
        # IMS Security Framework) -- a nonce request param is never
        # legitimate here. Anyone holding a captured id_token can trivially
        # read its nonce claim (JWTs aren't encrypted), so honoring an
        # attacker-supplied params["nonce"] that merely echoes the token's
        # own claim would make this check compare a value against itself,
        # defeating nonce-based replay protection entirely.
        expected_nonce = stored_nonce

        unless decoded.iss == options.issuer
          raise OmniAuth::Lti13::InvalidIdTokenError, "iss #{decoded.iss.inspect} does not match expected issuer"
        end

        unless Array(decoded.aud).include?(client_options.identifier)
          raise OmniAuth::Lti13::InvalidIdTokenError, "aud #{decoded.aud.inspect} does not include our client_id"
        end

        raise OmniAuth::Lti13::InvalidIdTokenError, "nonce does not match" unless decoded.nonce == expected_nonce
        raise OmniAuth::Lti13::ExpiredTokenError, decoded.exp unless decoded.exp.to_i + skew >= now

        if decoded.iat.to_i > now + skew
          raise OmniAuth::Lti13::InvalidIdTokenError, "iat #{decoded.iat.inspect} is too far in the future"
        end

        validate_azp!(decoded)
      end

      # azp (authorized party) is optional per the OIDC Core spec -- it only
      # needs checking when present, to disambiguate an aud with multiple
      # values. OmniAuth::Strategies::OpenIDConnect doesn't check it at all.
      def validate_azp!(decoded)
        return if decoded.azp.blank?
        return if decoded.azp == client_options.identifier

        log :warn, "id_token azp #{decoded.azp.inspect} does not match expected client_id " \
                    "#{client_options.identifier.inspect}"
        raise OmniAuth::Lti13::InvalidAzpError
      end

      # `iss` is guaranteed present on the initial (request-phase) launch,
      # per the IMS OIDC third-party-initiated login spec. Platforms aren't
      # guaranteed to resend it on the callback, so that leg reads the
      # issuer stashed in the session during the request phase instead --
      # deliberately *not* falling back to request.params["iss"] on the
      # callback leg: that would let a callback POST with no real prior
      # request-phase run (a missing/wiped session) select a platform from
      # an attacker-controlled iss. Failing closed here means a callback
      # that can't find its stashed issuer is simply unregistered, full
      # stop, rather than falling back to trusting the request itself.
      def current_iss
        on_request_path? ? request.params["iss"] : session["omniauth.lti13.iss"]
      end

      # Same reasoning and same fail-closed shape as current_iss above --
      # client_id disambiguates when a Platform's issuer is shared across
      # more than one of this tool's registrations (see PlatformRegistry).
      def current_client_id
        on_request_path? ? request.params["client_id"] : session["omniauth.lti13.client_id"]
      end

      # Rejecting a malformed login-initiation request here, before ever
      # redirecting the browser to the Platform, gives a clear tool-side
      # error instead of silently sending an authorize request that's
      # already missing data required by the flow.
      def validate_login_initiation!(platform)
        validate_client_id!(platform)

        missing = REQUIRED_INITIATION_PARAMS.select { |param| request.params[param].blank? }
        raise OmniAuth::Lti13::InvalidLoginInitiationError, missing unless missing.empty?
      end

      # client_id is optional on the login-initiation request (RECOMMENDED
      # by the IMS Security Framework for Platforms that register multiple
      # clients under one issuer) -- only rejects when it's present and
      # actually wrong, never used to pick the platform in the first place.
      def validate_client_id!(platform)
        incoming_client_id = request.params["client_id"]
        return if incoming_client_id.blank?
        return if incoming_client_id == platform.client_id

        log :warn, "login initiation client_id #{incoming_client_id.inspect} does not match registered " \
                    "client_id #{platform.client_id.inspect} for issuer #{platform.issuer.inspect}"
        raise OmniAuth::Lti13::ClientIdMismatchError
      end

      def apply_platform!(platform)
        @current_platform = platform
        options.issuer = platform.issuer
        client_options = options.client_options
        client_options.identifier = platform.client_id
        client_options.redirect_uri = platform.redirect_uri
        client_options.authorization_endpoint = platform.authorization_endpoint
        client_options.jwks_uri = platform.jwks_uri
      end

      # iss and client_id are already covered by platform lookup (setup_phase)
      # and this class's own aud verification (validate_claims!, via
      # verify_id_token! earlier in callback_phase) -- this is the last leg
      # of "iss + client_id + deployment_id together identify a registered
      # deployment" from the prompt: reject if the token's deployment_id
      # isn't one of the resolved platform's registered deployment_ids
      # (including if it's simply missing from the token).
      def validate_deployment!(claims)
        deployment_id = claims[OmniAuth::Lti13::Claims::DEPLOYMENT_ID]
        return if current_platform.deployment_id?(deployment_id)

        log :warn, "deployment_id #{deployment_id.inspect} is not registered for issuer " \
                    "#{current_platform.issuer.inspect} (registered: #{current_platform.deployment_ids.inspect})"
        raise OmniAuth::Lti13::DeploymentMismatchError
      end

      # `claims` is the id_token's raw_attributes: an
      # ActiveSupport::HashWithIndifferentAccess (json-jwt's JSON::JWT base
      # class) containing every claim in the token, standard and
      # LTI-specific alike.
      def build_auth_hash(claims)
        context = claims[OmniAuth::Lti13::Claims::CONTEXT] || {}
        label = context["label"].presence
        title = context["title"].presence

        AuthHash.new(
          provider: name,
          uid: claims["sub"],
          info: {
            email: claims["email"],
          },
          extra: {
            # label wins over title -- deliberately preserves 1.1 semantics,
            # where Course.title held the context label, not a full title.
            # title is only a fallback for a Platform that sends a title but
            # no label, so a Course isn't lost. See lti-gem-prompt.md's
            # "Course title/label semantics" section before changing this.
            context_id: context["id"],
            context_name: label || title,
            context_title: title,
            consumer: { context_label: label },
            roles: claims[OmniAuth::Lti13::Claims::ROLES],
          }
        )
      end
    end
  end
end
