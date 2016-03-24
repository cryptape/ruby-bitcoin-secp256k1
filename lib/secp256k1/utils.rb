module Secp256k1
  module Utils

    extend self

    def hash32(msg, raw, digest)
      msg32 = raw ? msg : digest.digest(msg)
      raise AssertError, "digest function must produce 256 bits" unless msg32.size == 32
      msg32
    end

    def encode_hex(b)
      b.unpack('H*').first
    end

    def decode_hex(s)
      [s].pack('H*')
    end

  end
end
