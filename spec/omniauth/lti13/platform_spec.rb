# frozen_string_literal: true

RSpec.describe OmniAuth::Lti13::Platform do
  let(:attrs) do
    {
      issuer: "https://canvas.example.edu",
      client_id: "canvas-client-id",
      deployment_ids: ["1:abc123", "1:def456"],
      authorization_endpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
      jwks_uri: "https://canvas.example.edu/api/lti/security/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  describe ".build" do
    it "builds a Platform from a plain Hash with symbol keys" do
      platform = described_class.build(attrs)

      expect(platform.issuer).to eq(attrs[:issuer])
      expect(platform.client_id).to eq(attrs[:client_id])
    end

    it "builds a Platform from a Hash with string keys" do
      platform = described_class.build(attrs.transform_keys(&:to_s))

      expect(platform.issuer).to eq(attrs[:issuer])
    end

    it "builds a Platform from an OmniAuth::Strategy::Options (Hashie::Mash), " \
       "which stringifies keys on write" do
      platform = described_class.build(OmniAuth::Strategy::Options.new(attrs))

      expect(platform.issuer).to eq(attrs[:issuer])
      expect(platform.deployment_ids).to eq(attrs[:deployment_ids])
    end

    it "passes through an existing Platform instance unchanged" do
      platform = described_class.new(**attrs)

      expect(described_class.build(platform)).to equal(platform)
    end
  end

  describe "#initialize" do
    it "raises ArgumentError listing every missing required attribute" do
      expect { described_class.new(**attrs.merge(issuer: "", client_id: "")) }
        .to raise_error(ArgumentError, /issuer.*client_id|client_id.*issuer/)
    end
  end

  describe "#deployment_id?" do
    it "is true for a configured deployment id" do
      platform = described_class.new(**attrs)

      expect(platform.deployment_id?("1:abc123")).to be true
    end

    it "is false for an unconfigured deployment id" do
      platform = described_class.new(**attrs)

      expect(platform.deployment_id?("unknown-deployment")).to be false
    end

    it "matches regardless of whether the configured id is a String or an Integer -- unquoted YAML " \
       "config (e.g. `deployment_ids: [1]`) parses a numeric-looking id as an Integer, but the LTI " \
       "deployment_id claim is always a String" do
      platform = described_class.new(**attrs.merge(deployment_ids: [1, "2"]))

      expect(platform.deployment_id?("1")).to be true
      expect(platform.deployment_id?(2)).to be true
    end
  end
end
