# frozen_string_literal: true

require "cgi"
require "uri"

RSpec.describe OmniAuth::Strategies::Lti13 do
  let(:app) { ->(_env) { [404, {}, ["Not Found"]] } }

  subject(:strategy) { described_class.new(app) }

  let(:canvas_platform) do
    {
      issuer: "https://canvas.example.edu",
      client_id: "canvas-client-id",
      deployment_ids: ["1:abc123"],
      authorization_endpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
      jwks_uri: "https://canvas.example.edu/api/lti/security/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  let(:blackboard_platform) do
    {
      issuer: "https://blackboard.example.edu",
      client_id: "blackboard-client-id",
      deployment_ids: ["deployment-1"],
      authorization_endpoint: "https://blackboard.example.edu/lti/authorize",
      jwks_uri: "https://blackboard.example.edu/lti/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  let(:valid_initiation_params) do
    {
      login_hint: "canvas-user-42",
      target_link_uri: "https://tool.example.org/users/auth/lti",
      lti_message_hint: "opaque-platform-generated-hint",
    }
  end

  let(:base_deployment_claim) do
    { "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => canvas_platform[:deployment_ids].first }
  end

  around do |example|
    original_validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
    OmniAuth.config.request_validation_phase = original_validation_phase
  end

  def to_query(params)
    params.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
  end

  # Builds the Rack app under test: this strategy mounted with the given
  # platforms, backed by a downstream app (defaulting to a plain 200) that
  # can be swapped in via a block to capture the env it received. By
  # default the strategy is configured with client_jwk_signing_key
  # (bypassing the jwks_uri network fetch); pass use_real_jwks_uri: true to
  # exercise that fetch instead (stub it with WebMock at the platform's
  # jwks_uri).
  def build_rack_app(platforms:, use_real_jwks_uri: false, &downstream)
    jwk_hash = jwk.to_h
    downstream_app = downstream || ->(_env) { [200, {}, ["ok"]] }

    Rack::Builder.new do
      strategy_options = { platforms: platforms }
      strategy_options[:client_jwk_signing_key] = jwk_hash unless use_real_jwks_uri
      use OmniAuth::Strategies::Lti13, **strategy_options
      run downstream_app
    end.to_app
  end

  # Shared assertion for the many failure-path tests below: the launch was
  # rejected before ever reaching the downstream/protected app, and the
  # response is the standard OmniAuth failure redirect.
  def expect_launch_rejected(response, env)
    expect(env).to be_nil
    expect(response.status).to eq(302)
    expect(response.location).to start_with("/auth/failure")
  end

  it "is a subclass of OmniAuth::Strategies::OpenIDConnect" do
    expect(described_class.superclass).to eq(OmniAuth::Strategies::OpenIDConnect)
  end

  it "answers on the 'lti' path, not the inherited 'openid_connect' path" do
    expect(strategy.options.name).to eq("lti")
  end

  describe "request phase (third-party initiated login)" do
    # OmniAuth 2.x's OmniAuth::AuthenticityTokenProtection rejects
    # cross-site request-phase POSTs by default -- which is exactly what a
    # real LTI third-party-initiated login is. That check is global
    # (OmniAuth.config.request_validation_phase), not per-strategy, so a
    # scoped exemption for the LTI login-initiation route is Avalon's
    # integration responsibility, not something this gem can/should do.
    # Disabled (see the top-level `around` above) only so these specs can
    # test routing/resolution, not that concern.

    def post_to_request_phase(platforms:, params:)
      rack_app = build_rack_app(platforms: platforms)
      env = Rack::MockRequest.env_for("/auth/lti?#{to_query(params)}", method: "POST", "rack.session" => {})
      Rack::MockResponse.new(*rack_app.call(env))
    end

    def redirect_query_params(response)
      URI.decode_www_form(URI(response.location).query).to_h
    end

    it "mounts at /auth/lti and redirects to the resolved platform's authorization endpoint " \
       "(Avalon/Devise then prefixes this with /users)" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(canvas_platform[:authorization_endpoint])
    end

    it "selects the correct platform by iss when multiple are registered" do
      response = post_to_request_phase(
        platforms: [canvas_platform, blackboard_platform],
        params: valid_initiation_params.merge(iss: blackboard_platform[:issuer])
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(blackboard_platform[:authorization_endpoint])
    end

    it "disambiguates by client_id when multiple platforms share an issuer " \
       "(e.g. Canvas Cloud's shared issuer across tenants)" do
      tenant_a = canvas_platform.merge(client_id: "tenant-a", authorization_endpoint: "https://canvas.example.edu/a")
      tenant_b = canvas_platform.merge(client_id: "tenant-b", authorization_endpoint: "https://canvas.example.edu/b")

      response = post_to_request_phase(
        platforms: [tenant_a, tenant_b],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer], client_id: "tenant-b")
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(tenant_b[:authorization_endpoint])
    end

    it "rejects a launch when multiple platforms share an issuer and client_id is omitted, " \
       "rather than guessing which one is meant" do
      tenant_a = canvas_platform.merge(client_id: "tenant-a")
      tenant_b = canvas_platform.merge(client_id: "tenant-b")

      response = post_to_request_phase(
        platforms: [tenant_a, tenant_b],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
    end

    it "rejects a launch from an unregistered iss instead of falling back to a default" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: "https://unregistered.example.edu")
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("no+registered+LTI+platform")
    end

    it "builds the authorization request with response_type=id_token and response_mode=form_post" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["response_type"]).to eq("id_token")
      expect(redirect_params["response_mode"]).to eq("form_post")
      expect(redirect_params["scope"]).to eq("openid")
    end

    it "threads login_hint, lti_message_hint, and target_link_uri through to the authorization request " \
       "unmodified, without dropping lti_message_hint" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["login_hint"]).to eq(valid_initiation_params[:login_hint])
      expect(redirect_params["lti_message_hint"]).to eq(valid_initiation_params[:lti_message_hint])
      expect(redirect_params["target_link_uri"]).to eq(valid_initiation_params[:target_link_uri])
    end

    it "does not forward the login-initiation client_id param as an authorize param, since the " \
       "resolved platform's registered client_id already drives the authorization request" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer], client_id: canvas_platform[:client_id])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["client_id"]).to eq(canvas_platform[:client_id])
    end

    it "rejects a login-initiation client_id that doesn't match the resolved platform's registered client_id" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer], client_id: "some-other-client-id")
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("client_id")
    end

    it "rejects a login-initiation request missing required params (login_hint, target_link_uri)" do
      response = post_to_request_phase(platforms: [canvas_platform], params: { iss: canvas_platform[:issuer] })

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("login_hint")
      expect(response.location).to include("target_link_uri")
    end
  end

  # Builds the Rack app + runs the request phase, leaving `session`
  # populated with omniauth.state/omniauth.nonce/omniauth.lti13.iss the way
  # a real request-phase redirect would. Returns [rack_app, session] so the
  # callback leg can be driven separately (perform_callback_phase below),
  # or driven more than once against the same session (replay tests).
  def perform_request_phase(platforms:, issuer:, client_id: nil, use_real_jwks_uri: false)
    session = {}
    rack_app = build_rack_app(platforms: platforms, use_real_jwks_uri: use_real_jwks_uri)

    initiation_params = valid_initiation_params.merge(iss: issuer)
    initiation_params[:client_id] = client_id if client_id
    request_env = Rack::MockRequest.env_for(
      "/auth/lti?#{to_query(initiation_params)}", method: "POST", "rack.session" => session
    )
    rack_app.call(request_env)

    [rack_app, session]
  end

  # Posts id_token/state to the callback path against a freshly-built rack
  # app sharing the given session (from perform_request_phase). Returns the
  # response and the env the downstream app received (so
  # env["omniauth.auth"] can be inspected).
  def perform_callback_phase(platforms:, session:, id_token:, state:, use_real_jwks_uri: false, extra_params: {})
    downstream_env = nil
    rack_app = build_rack_app(platforms: platforms, use_real_jwks_uri: use_real_jwks_uri) do |env|
      downstream_env = env
      [200, {}, ["ok"]]
    end

    callback_query = to_query({ id_token: id_token, state: state }.merge(extra_params))
    callback_env = Rack::MockRequest.env_for(
      "/auth/lti/callback?#{callback_query}", method: "POST", "rack.session" => session
    )
    callback_response = Rack::MockResponse.new(*rack_app.call(callback_env))

    [callback_response, downstream_env]
  end

  # Drives a full launch through both legs (request phase, then callback)
  # against a real self-signed id_token, sharing one session Hash across
  # both Rack calls the way a browser's session cookie would. Returns the
  # callback response, the env the downstream app received, and the
  # session Hash (so replay-style tests can drive a second callback against
  # the same, now-partially-consumed, session).
  def perform_full_launch(platforms:, issuer:, client_id:, extra_claims: {},
                           jwt_alg: :RS256, jwt_key: rsa_key, jwt_kid: nil, use_real_jwks_uri: false,
                           state_override: nil, nonce_override: nil, initiation_client_id: nil)
    _rack_app, session = perform_request_phase(
      platforms: platforms, issuer: issuer, client_id: initiation_client_id, use_real_jwks_uri: use_real_jwks_uri
    )

    claims = {
      iss: issuer,
      sub: "user-42",
      aud: client_id,
      exp: (Time.now + 300).to_i,
      iat: Time.now.to_i,
      nonce: nonce_override || session["omniauth.nonce"],
    }.merge(extra_claims)
    id_token = build_id_token(claims, key: jwt_key, alg: jwt_alg, kid: jwt_kid)

    response, env = perform_callback_phase(
      platforms: platforms,
      session: session,
      id_token: id_token,
      state: state_override || session["omniauth.state"],
      use_real_jwks_uri: use_real_jwks_uri
    )

    [response, env, session]
  end

  describe "callback phase (full launch)" do
    it "maps a full claim set into the five-plus-one auth_hash contract Avalon expects" do
      _response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim.merge(
          email: "student@example.edu",
          "https://purl.imsglobal.org/spec/lti/claim/context" => {
            "id" => "course-123",
            "label" => "TEST101",
            "title" => "Introduction to Testing",
          },
          "https://purl.imsglobal.org/spec/lti/claim/roles" => ["Learner"]
        )
      )

      auth_hash = env["omniauth.auth"]

      expect(auth_hash.uid).to eq("user-42")
      expect(auth_hash.info.email).to eq("student@example.edu")
      expect(auth_hash.extra.context_id).to eq("course-123")
      expect(auth_hash.extra.context_name).to eq("TEST101")
      expect(auth_hash.extra.consumer.context_label).to eq("TEST101")
      expect(auth_hash.extra.context_title).to eq("Introduction to Testing")
      expect(auth_hash.extra.roles).to eq(["Learner"])
    end

    it "resolves the correct platform on the callback leg too, via the client_id stashed during the request " \
       "phase, when multiple platforms share an issuer" do
      tenant_a = canvas_platform.merge(client_id: "tenant-a", deployment_ids: ["tenant-a-deployment"])
      tenant_b = canvas_platform.merge(client_id: "tenant-b", deployment_ids: ["tenant-b-deployment"])

      _response, env = perform_full_launch(
        platforms: [tenant_a, tenant_b],
        issuer: canvas_platform[:issuer],
        client_id: "tenant-b",
        initiation_client_id: "tenant-b",
        extra_claims: {
          "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => "tenant-b-deployment",
        }
      )

      expect(env["omniauth.auth"]).not_to be_nil
      expect(env["omniauth.auth"].uid).to eq("user-42")
    end

    it "rejects a token whose deployment_id isn't registered for the platform" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: {
          "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => "some-unregistered-deployment",
        }
      )

      expect_launch_rejected(response, env)
    end

    it "rejects a token missing deployment_id entirely" do
      response, env = perform_full_launch(
        platforms: [canvas_platform], issuer: canvas_platform[:issuer], client_id: canvas_platform[:client_id]
      )

      expect_launch_rejected(response, env)
    end

    it "rejects a token with a missing sub (relying on the base gem's attr_required check)" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim.merge(sub: nil)
      )

      expect_launch_rejected(response, env)
    end

    it "rejects a token with a blank (empty string) sub" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim.merge(sub: "")
      )

      expect_launch_rejected(response, env)
    end

    it "populates info.email as an explicit nil, without erroring, when the email claim is absent" do
      _response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim
      )

      auth_hash = env["omniauth.auth"]
      expect(auth_hash).not_to be_nil
      expect(auth_hash.info.key?("email")).to be true
      expect(auth_hash.info.email).to be_nil
    end
  end

  describe "nonce/state replay protection (via omniauth_openid_connect)" do
    it "rejects a callback whose state doesn't match what was stored during the request phase" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim,
        state_override: "forged-state-value"
      )

      expect_launch_rejected(response, env)
    end

    it "rejects a callback whose id_token nonce doesn't match what was stored during the request phase" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: base_deployment_claim,
        nonce_override: "forged-nonce-value"
      )

      expect_launch_rejected(response, env)
    end

    it "does not honor a nonce request param, even one crafted to match the id_token's own nonce claim -- " \
       "otherwise an attacker holding any captured id_token (JWTs aren't encrypted, so its nonce claim is " \
       "trivially readable) could replay it into a session of their own by echoing that nonce back as a " \
       "request param, defeating nonce-based replay protection" do
      platforms = [canvas_platform]

      # A token legitimately issued for some other (e.g. victim's) session.
      _rack_app, other_session = perform_request_phase(platforms: platforms, issuer: canvas_platform[:issuer])
      captured_claims = {
        iss: canvas_platform[:issuer],
        sub: "victim-user",
        aud: canvas_platform[:client_id],
        exp: (Time.now + 300).to_i,
        iat: Time.now.to_i,
        nonce: other_session["omniauth.nonce"],
      }.merge(base_deployment_claim)
      captured_id_token = build_id_token(captured_claims)
      captured_nonce = other_session["omniauth.nonce"]

      # Attacker's own session/request phase (its own state/nonce, unrelated to the captured token).
      _rack_app, attacker_session = perform_request_phase(platforms: platforms, issuer: canvas_platform[:issuer])

      response, env = perform_callback_phase(
        platforms: platforms,
        session: attacker_session,
        id_token: captured_id_token,
        state: attacker_session["omniauth.state"],
        extra_params: { nonce: captured_nonce }
      )

      expect_launch_rejected(response, env)
    end

    it "rejects a second callback that replays the same state/nonce (both are session.delete-based, one-time use)" do
      platforms = [canvas_platform]
      _rack_app, session = perform_request_phase(platforms: platforms, issuer: canvas_platform[:issuer])

      claims = {
        iss: canvas_platform[:issuer],
        sub: "user-42",
        aud: canvas_platform[:client_id],
        exp: (Time.now + 300).to_i,
        iat: Time.now.to_i,
        nonce: session["omniauth.nonce"],
      }.merge(base_deployment_claim)
      id_token = build_id_token(claims)
      state = session["omniauth.state"]

      first_response, first_env = perform_callback_phase(
        platforms: platforms, session: session, id_token: id_token, state: state
      )
      expect(first_env["omniauth.auth"]).not_to be_nil
      expect(first_response.status).to eq(200)

      second_response, second_env = perform_callback_phase(
        platforms: platforms, session: session, id_token: id_token, state: state
      )

      expect_launch_rejected(second_response, second_env)
    end
  end

  describe "#build_auth_hash (private; exercised directly for the context label/title precedence matrix)" do
    def claims_with_context(context)
      {
        "sub" => "user-42",
        "email" => "student@example.edu",
        "https://purl.imsglobal.org/spec/lti/claim/context" => context,
      }
    end

    it "prefers label over title for context_name when both are present " \
       "(guards against mapping title instead)" do
      claims = claims_with_context("id" => "course-123", "label" => "TEST101", "title" => "Intro to Testing")
      auth_hash = strategy.send(:build_auth_hash, claims)

      expect(auth_hash.extra.context_name).to eq("TEST101")
      expect(auth_hash.extra.context_title).to eq("Intro to Testing")
      expect(auth_hash.extra.consumer.context_label).to eq("TEST101")
    end

    it "creates a Course from label alone" do
      claims = claims_with_context("id" => "course-123", "label" => "TEST101")
      auth_hash = strategy.send(:build_auth_hash, claims)

      expect(auth_hash.extra.context_name).to eq("TEST101")
    end

    it "falls back to title when label is absent, so the Course isn't lost" do
      claims = claims_with_context("id" => "course-123", "title" => "Intro to Testing")
      auth_hash = strategy.send(:build_auth_hash, claims)

      expect(auth_hash.extra.context_name).to eq("Intro to Testing")
    end

    it "is an explicit nil (not an absent key) when the context claim carries neither label nor title, " \
       "and does not create a Course" do
      claims = claims_with_context("id" => "course-123")
      auth_hash = strategy.send(:build_auth_hash, claims)

      expect(auth_hash.extra.key?("context_name")).to be true
      expect(auth_hash.extra.context_name).to be_nil
    end
  end

  describe "security hardening" do
    describe "JWT algorithm allowlist" do
      it "rejects alg: none (the classic unsigned-token forgery vector)" do
        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim,
          jwt_alg: :none
        )

        expect_launch_rejected(response, env)
      end

      it "rejects an algorithm outside the allowlist even when the token is validly signed" do
        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim,
          jwt_alg: :HS256,
          jwt_key: "shared-secret-no-real-platform-would-use-for-lti"
        )

        expect_launch_rejected(response, env)
      end
    end

    describe "exp/iat clock-skew tolerance (default 60s)" do
      it "rejects a token expired beyond the skew tolerance" do
        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim.merge(exp: Time.now.to_i - 90)
        )

        expect_launch_rejected(response, env)
      end

      it "accepts a token expired within the skew tolerance" do
        _response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim.merge(exp: Time.now.to_i - 30)
        )

        expect(env["omniauth.auth"]).not_to be_nil
      end

      it "rejects a token whose iat is too far in the future, beyond the skew tolerance" do
        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim.merge(iat: Time.now.to_i + 120)
        )

        expect_launch_rejected(response, env)
      end
    end

    describe "azp validation" do
      it "rejects an azp that doesn't match the resolved platform's client_id" do
        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim.merge(azp: "some-other-client-id")
        )

        expect_launch_rejected(response, env)
      end

      it "accepts a token whose azp matches the resolved platform's client_id" do
        _response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim.merge(azp: canvas_platform[:client_id])
        )

        expect(env["omniauth.auth"]).not_to be_nil
      end
    end

    describe "JWKS rotation" do
      it "retries with a freshly re-fetched JWKS when the token's key isn't in the first fetch, " \
         "so a Platform that rotated its signing key doesn't fail every launch until we happen to refetch" do
        other_key = OpenSSL::PKey::RSA.generate(2048)
        stale_jwk = JSON::JWK.new(other_key.public_key, kid: "old-key")
        current_jwk = JSON::JWK.new(rsa_key.public_key, kid: "current-key")

        stub_request(:get, canvas_platform[:jwks_uri])
          .to_return(body: build_jwks(stale_jwk).to_json, headers: { "Content-Type" => "application/json" })
          .then
          .to_return(
            body: build_jwks(stale_jwk, current_jwk).to_json, headers: { "Content-Type" => "application/json" }
          )

        _response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim,
          jwt_kid: "current-key",
          use_real_jwks_uri: true
        )

        expect(env["omniauth.auth"]).not_to be_nil
        expect(WebMock).to have_requested(:get, canvas_platform[:jwks_uri]).twice
      end

      it "still fails if the key isn't in the freshly re-fetched JWKS either (one retry, not infinite)" do
        other_key = OpenSSL::PKey::RSA.generate(2048)
        stale_jwk = JSON::JWK.new(other_key.public_key, kid: "old-key")

        stub_request(:get, canvas_platform[:jwks_uri])
          .to_return(body: build_jwks(stale_jwk).to_json, headers: { "Content-Type" => "application/json" })

        response, env = perform_full_launch(
          platforms: [canvas_platform],
          issuer: canvas_platform[:issuer],
          client_id: canvas_platform[:client_id],
          extra_claims: base_deployment_claim,
          jwt_kid: "current-key",
          use_real_jwks_uri: true
        )

        expect_launch_rejected(response, env)
      end
    end
  end
end
