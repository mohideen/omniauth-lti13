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
    # Disabled here only so these specs can test routing/resolution, not
    # that concern.
    around do |example|
      original_validation_phase = OmniAuth.config.request_validation_phase
      OmniAuth.config.request_validation_phase = nil
      example.run
      OmniAuth.config.request_validation_phase = original_validation_phase
    end

    def post_to_request_phase(platforms:, params:)
      rack_app = Rack::Builder.new do
        use OmniAuth::Strategies::Lti13, platforms: platforms
        run ->(_env) { [404, {}, ["Not Found"]] }
      end.to_app

      query = params.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
      env = Rack::MockRequest.env_for("/auth/lti?#{query}", method: "POST", "rack.session" => {})
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

  describe "callback phase (full launch)" do
    around do |example|
      original_validation_phase = OmniAuth.config.request_validation_phase
      OmniAuth.config.request_validation_phase = nil
      example.run
      OmniAuth.config.request_validation_phase = original_validation_phase
    end

    # Drives a full launch through both legs (request phase, then callback)
    # against a real self-signed id_token, sharing one session Hash across
    # both Rack calls the way a browser's session cookie would. Returns the
    # callback response and the env the downstream app received (so
    # env["omniauth.auth"] can be inspected).
    def perform_full_launch(platforms:, issuer:, client_id:, extra_claims: {})
      session = {}
      downstream_env = nil
      jwk_hash = jwk.to_h
      rack_app = Rack::Builder.new do
        use OmniAuth::Strategies::Lti13, platforms: platforms, client_jwk_signing_key: jwk_hash
        run ->(env) do
          downstream_env = env
          [200, {}, ["ok"]]
        end
      end.to_app

      request_query = valid_initiation_params.merge(iss: issuer).map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
      request_env = Rack::MockRequest.env_for("/auth/lti?#{request_query}", method: "POST", "rack.session" => session)
      rack_app.call(request_env)

      claims = {
        iss: issuer,
        sub: "user-42",
        aud: client_id,
        exp: (Time.now + 300).to_i,
        iat: Time.now.to_i,
        nonce: session["omniauth.nonce"],
      }.merge(extra_claims)
      id_token = build_id_token(claims)

      callback_query = { id_token: id_token, state: session["omniauth.state"] }
                        .map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
      callback_env = Rack::MockRequest.env_for(
        "/auth/lti/callback?#{callback_query}", method: "POST", "rack.session" => session
      )
      callback_response = Rack::MockResponse.new(*rack_app.call(callback_env))

      [callback_response, downstream_env]
    end

    it "maps a full claim set into the five-plus-one auth_hash contract Avalon expects" do
      _response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: {
          email: "student@example.edu",
          "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => canvas_platform[:deployment_ids].first,
          "https://purl.imsglobal.org/spec/lti/claim/context" => {
            "id" => "course-123",
            "label" => "TEST101",
            "title" => "Introduction to Testing",
          },
          "https://purl.imsglobal.org/spec/lti/claim/roles" => ["Learner"],
        }
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

    it "rejects a token whose deployment_id isn't registered for the platform" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: {
          "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => "some-unregistered-deployment",
        }
      )

      expect(env).to be_nil # call_app! (the downstream/protected app) never ran
      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
    end

    it "rejects a token missing deployment_id entirely" do
      response, env = perform_full_launch(
        platforms: [canvas_platform], issuer: canvas_platform[:issuer], client_id: canvas_platform[:client_id]
      )

      expect(env).to be_nil # call_app! (the downstream/protected app) never ran
      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
    end

    it "rejects a token with a blank/missing sub (relying on the base gem's attr_required check)" do
      response, env = perform_full_launch(
        platforms: [canvas_platform],
        issuer: canvas_platform[:issuer],
        client_id: canvas_platform[:client_id],
        extra_claims: {
          sub: nil,
          "https://purl.imsglobal.org/spec/lti/claim/deployment_id" => canvas_platform[:deployment_ids].first,
        }
      )

      expect(env).to be_nil # call_app! (the downstream/protected app) never ran
      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
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
end
