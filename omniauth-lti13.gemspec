# frozen_string_literal: true

require_relative "lib/omniauth/lti13/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-lti13"
  spec.version = OmniAuth::Lti13::VERSION
  spec.authors = ["Avalon Media System"]
  spec.email = ["mohideen87@gmail.com"]

  spec.summary = "OmniAuth strategy for LTI 1.3 (IMS Core launch/auth) built on omniauth_openid_connect."
  spec.description = "Implements the LTI 1.3 third-party-initiated OIDC login and launch flow as an " \
                      "OmniAuth strategy, mapping LTI claims to an OmniAuth auth_hash. Built on top of " \
                      "omniauth_openid_connect rather than reimplementing OIDC/JWT handling. LTI Advantage " \
                      "(Deep Linking, AGS, NRPS) is out of scope."
  spec.homepage = "https://github.com/avalonmediasystem/omniauth-lti13"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/avalonmediasystem/omniauth-lti13"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .rspec spec/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "omniauth_openid_connect", "~> 0.8"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
