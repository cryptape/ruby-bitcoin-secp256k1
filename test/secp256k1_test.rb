# -*- encoding : ascii-8bit -*-

$:.unshift File.expand_path('../../lib', __FILE__)

require 'minitest/autorun'
require 'secp256k1'

require 'json'

class MyECDSA < Secp256k1::BaseKey
  include Secp256k1::Utils, Secp256k1::ECDSA

  def initialize
    super(nil, Secp256k1::ALL_FLAGS)
  end
end

class Secp256k1Test < Minitest::Test
  include Secp256k1

  def test_ecdsa
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

  def test_ecdsa_compact
    pk = PrivateKey.new
    raw_sig = pk.ecdsa_sign 'test'
    assert_equal true, pk.pubkey.ecdsa_verify('test', raw_sig)

    compact = pk.ecdsa_serialize_compact raw_sig
    assert_equal 64, compact.size

    sig_raw = pk.ecdsa_deserialize_compact compact
    assert_equal compact, pk.ecdsa_serialize_compact(sig_raw)
    assert_equal true, pk.pubkey.ecdsa_verify('test', sig_raw)
  end

  def test_ecdsa_normalize
    pk = PrivateKey.new
    raw_sig = pk.ecdsa_sign 'hi'

    had_to_normalize, normsig = pk.ecdsa_signature_normalize raw_sig
    assert_equal false, had_to_normalize
    assert_equal pk.ecdsa_serialize(raw_sig), pk.ecdsa_serialize(normsig)
    assert_equal pk.ecdsa_serialize_compact(raw_sig), pk.ecdsa_serialize_compact(normsig)

    had_to_normalize, normsig = pk.ecdsa_signature_normalize(raw_sig, check_only: true)
    assert_equal false, had_to_normalize
    assert_nil normsig

    sig = "\xAA" + "\xFF"*31 + "\xAA" + "\xFF"*31
    raw_sig = pk.ecdsa_deserialize_compact sig

    normalized, normsig = pk.ecdsa_signature_normalize raw_sig
    assert_equal true, normalized
    assert pk.ecdsa_serialize(raw_sig) != pk.ecdsa_serialize(normsig)

    normalized, normsig = pk.ecdsa_signature_normalize raw_sig, check_only: true
    assert_equal true, normalized
    assert_nil normsig
  end

  def test_ecdsa_recover
    return unless C.module_recovery_enabled?

    pk = PrivateKey.new
    unrelated = MyECDSA.new

    recsig = pk.ecdsa_sign_recoverable 'hello'
    pubkey = unrelated.ecdsa_recover 'hello', recsig
    pubser = PublicKey.new(pubkey: pubkey).serialize
    assert_equal pubser, pk.pubkey.serialize

    recsig_ser = unrelated.ecdsa_recoverable_serialize recsig
    recsig2 = unrelated.ecdsa_recoverable_deserialize(*recsig_ser)
    pubkey2 = unrelated.ecdsa_recover 'hello', recsig2
    pubser2 = PublicKey.new(pubkey: pubkey2).serialize
    assert_equal pubser, pubser2

    raw_sig = unrelated.ecdsa_recoverable_convert recsig2
    unrelated.ecdsa_deserialize(unrelated.ecdsa_serialize(raw_sig))
  end

  private

  def ecdsa_sig
    @ecdsa_sig = JSON.parse File.read(File.expand_path('../fixtures/ecdsa_sig.json', __FILE__))
  end

end
