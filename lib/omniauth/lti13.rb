# frozen_string_literal: true

require_relative "lti13/version"
require_relative "strategies/lti13"

module OmniAuth
  module Lti13
    class Error < StandardError; end
  end
end
