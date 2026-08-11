# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::Lti13 do
  let(:app) { ->(_env) { [404, {}, ["Not Found"]] } }

  subject(:strategy) { described_class.new(app) }

  it "is a subclass of OmniAuth::Strategies::OpenIDConnect" do
    expect(described_class.superclass).to eq(OmniAuth::Strategies::OpenIDConnect)
  end

  it "answers on the 'lti' path, not the inherited 'openid_connect' path" do
    expect(strategy.options.name).to eq("lti")
  end

  it "mounts at /auth/lti (Avalon/Devise then prefixes this with /users), answering on POST " \
     "per OmniAuth's default allowed_request_methods" do
    # OmniAuth 2.x's OmniAuth::AuthenthenticityTokenProtection rejects
    # cross-site request-phase POSTs by default -- which is exactly what a
    # real LTI third-party-initiated login is. That check is global
    # (OmniAuth.config.request_validation_phase), not per-strategy, so a
    # scoped exemption for the LTI login-initiation route is Avalon's
    # integration responsibility, not something this gem can/should do.
    # Disabled here only so this spec can test routing, not that concern.
    original_validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil

    rack_app = Rack::Builder.new do
      use OmniAuth::Strategies::Lti13,
          issuer: "https://idp.example.org",
          client_options: {
            identifier: "test-client",
            redirect_uri: "https://tool.example.org/auth/lti/callback",
            scheme: "https",
            host: "idp.example.org",
            authorization_endpoint: "/authorize",
          }
      run ->(_env) { [404, {}, ["Not Found"]] }
    end.to_app

    env = Rack::MockRequest.env_for("/auth/lti", method: "POST", "rack.session" => {})
    response = Rack::MockResponse.new(*rack_app.call(env))

    expect(response.status).to eq(302)
    expect(response.location).to start_with("https://idp.example.org/authorize")
  ensure
    OmniAuth.config.request_validation_phase = original_validation_phase
  end
end
