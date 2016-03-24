# -*- encoding : ascii-8bit -*-

$:.unshift File.expand_path('../../lib', __FILE__)

require 'minitest/autorun'
require 'secp256k1'

class Secp256k1Test < Minitest::Test

  def test_hello_world
    p Secp256k1::EC_COMPRESSED
  end

end
