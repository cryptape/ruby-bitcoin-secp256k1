module Secp256k1
  module ECDSA

    SIZE_SERIALIZED = 74

    def ecdsa_serialize(raw_sig)
      output = FFI::MemoryPointer.new(:uchar, SIZE_SERIALIZED)
      outputlen = FFI::MemoryPointer.new(:size_t).put_uint(0, SIZE_SERIALIZED)

      res = C.secp256k1_ecdsa_signature_serialize_der(@ctx, output, outputlen, raw_sig)
      raise AssertError, "failed to seriazlie signature" unless res == 1

      output.read_bytes(outputlen.read_uint)
    end

  end
end
