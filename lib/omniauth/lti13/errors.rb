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
  end
end
