# frozen_string_literal: true

module OmniAuth
  module Lti13
    # A single registered LTI 1.3 Platform (an LMS instance, e.g. one Canvas
    # account). See the README for the full config schema Avalon populates
    # this from -- this class is the runtime representation of one entry.
    class Platform
      attr_reader :issuer, :client_id, :deployment_ids, :authorization_endpoint, :jwks_uri, :redirect_uri

      REQUIRED_ATTRIBUTES = %i[issuer client_id deployment_ids authorization_endpoint jwks_uri redirect_uri].freeze

      def self.build(attrs)
        return attrs if attrs.is_a?(Platform)

        # `attrs` may be a Hashie::Mash (OmniAuth's Options are Mashes,
        # which stringify keys on write -- transform_keys(&:to_sym) alone
        # is a no-op on one, since re-inserting a symbol key just gets it
        # stringified again). Round-trip through a plain Hash first so the
        # keyword splat below actually gets Symbol keys.
        new(**attrs.to_hash.transform_keys(&:to_sym))
      end

      def initialize(issuer:, client_id:, deployment_ids:, authorization_endpoint:, jwks_uri:, redirect_uri:)
        @issuer = issuer
        @client_id = client_id
        # Coerced to strings: the LTI deployment_id claim is always a JSON
        # string, but YAML config (settings.yml) parses an unquoted numeric
        # deployment_id (e.g. `deployment_ids: [1]`) as an Integer, and
        # `[1].include?("1")` is false -- comparing as anything other than
        # strings would silently reject every launch from a deployment_id
        # that happens to look numeric.
        @deployment_ids = Array(deployment_ids).map(&:to_s)
        @authorization_endpoint = authorization_endpoint
        @jwks_uri = jwks_uri
        @redirect_uri = redirect_uri

        validate_required_attributes!
      end

      def deployment_id?(deployment_id)
        deployment_ids.include?(deployment_id.to_s)
      end

      private

      def validate_required_attributes!
        missing = REQUIRED_ATTRIBUTES.select { |attr| public_send(attr).blank? }

        raise ArgumentError, "Platform missing required attribute(s): #{missing.join(', ')}" if missing.any?
      end
    end
  end
end
