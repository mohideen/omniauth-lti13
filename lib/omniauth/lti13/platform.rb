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
        @deployment_ids = Array(deployment_ids)
        @authorization_endpoint = authorization_endpoint
        @jwks_uri = jwks_uri
        @redirect_uri = redirect_uri

        validate_required_attributes!
      end

      def deployment_id?(deployment_id)
        deployment_ids.include?(deployment_id)
      end

      private

      def validate_required_attributes!
        missing = REQUIRED_ATTRIBUTES.select { |attr| public_send(attr).blank? }

        raise ArgumentError, "Platform missing required attribute(s): #{missing.join(', ')}" if missing.any?
      end
    end
  end
end
