# -*- encoding : ascii-8bit -*-

$:.unshift File.expand_path('../../lib', __FILE__)

require 'minitest/autorun'
require 'secp256k1'

require 'json'

class Secp256k1Test < Minitest::Test
  include Secp256k1

  def test_ecdsa_sign
    vec = ecdsa_sig['vectors']
    pk = PrivateKey.new

    vec.each do |item|
      seckey = Utils.decode_hex item['privkey']
      msg32 = Utils.decode_hex item['msg']
      sig = Utils.decode_hex(item['sig'])[0...-1]

      pk.set_raw_privkey seckey

      sig_raw = pk.ecdsa_sign msg32, raw: true
      sig_check = pk.ecdsa_serialize sig_raw

      assert_equal sig, sig_check
      assert_equal sig_check, pk.ecdsa_serialize(pk.ecdsa_deserialize(sig_check))
    end
  end

  private

  def ecdsa_sig
    @ecdsa_sig = JSON.parse File.read(File.expand_path('../fixtures/ecdsa_sig.json', __FILE__))
  end

end
