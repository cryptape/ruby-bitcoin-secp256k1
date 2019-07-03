$:.push File.expand_path("../lib", __FILE__)

require 'secp256k1/version'

Gem::Specification.new do |s|
  s.name        = "bitcoin-secp256k1"
  s.version     = Secp256k1::VERSION
  s.authors     = ["Jan Xie"]
  s.email       = ["jan.h.xie@gmail.com"]
  s.homepage    = "https://github.com/cryptape/ruby-bitcoin-secp256k1"
  s.summary     = "Ruby binding to bitcoin's secp256k1 implementation."
  s.description = "Ruby binding to bitcoin's secp256k1 implementation."
  s.license     = 'MIT'

  s.files      = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")

  s.add_dependency('ffi', '>= 1.9.25')

  s.add_development_dependency('rake', '~> 12.3')
  s.add_development_dependency('minitest', '5.11.3')
  s.add_development_dependency('yard', '0.9.20')
end
