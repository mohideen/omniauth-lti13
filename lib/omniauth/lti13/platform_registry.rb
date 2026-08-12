# frozen_string_literal: true

module OmniAuth
  module Lti13
    # Looks up a registered Platform by issuer. Built from the strategy's
    # `:platforms` option (an Array of Hashes or Platform instances) --
    # see the README for the config schema.
    class PlatformRegistry
      def initialize(platforms)
        @platforms_by_issuer = Array(platforms).each_with_object({}) do |attrs, memo|
          platform = Platform.build(attrs)
          memo[platform.issuer] = platform
        end
      end

      def find_by_issuer(issuer)
        return nil if issuer.blank?

        @platforms_by_issuer[issuer]
      end
    end
  end
end
