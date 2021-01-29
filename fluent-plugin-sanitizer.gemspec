lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-sanitizer"
  spec.version = "0.1.0"
  spec.authors = ["TK Kubota"]
  spec.email   = ["tkubota@ctc-america.com"]

  spec.summary       = %q{Filter plugin of Fluentd which sanitize sensitive information.}
  spec.description   = %q{The fluent-plugin-sanitzer is Fluentd filter plugin to sanitize sensitive information with custom rules. The fluent-plugin-sanitzer provides not only options to sanitize values with custom regular expression and keywords but also build-in options which allows users to easily sanitize IP addresses and hostnames in complex messages.}
  spec.homepage      = "https://github.com/fluent/fluent-plugin-sanitizer"
  spec.license       = "Apache-2.0"

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "test-unit", "~> 3.0"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
end
