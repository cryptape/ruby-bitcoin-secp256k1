module Secp256k1
  module ECDSA

    SIZE_SERIALIZED = 74
    SIZE_COMPACT = 64

    def ecdsa_serialize(raw_sig)
      output = FFI::MemoryPointer.new(:uchar, SIZE_SERIALIZED)
      outputlen = FFI::MemoryPointer.new(:size_t).put_uint(0, SIZE_SERIALIZED)

      res = C.secp256k1_ecdsa_signature_serialize_der(@ctx, output, outputlen, raw_sig)
      raise AssertError, "failed to seriazlie signature" unless res == 1

      output.read_bytes(outputlen.read_uint)
    end

    def ecdsa_deserialize(ser_sig)
      raw_sig = C::ECDSASignature.new.pointer

      res = C.secp256k1_ecdsa_signature_parse_der(@ctx, raw_sig, ser_sig, ser_sig.size)
      raise AssertError, "raw signature parse failed" unless res == 1

      raw_sig
    end

    def ecdsa_serialize_compact(raw_sig)
      output = FFI::MemoryPointer.new(:uchar, SIZE_COMPACT)

      res = C.secp256k1_ecdsa_signature_serialize_compact(@ctx, output, raw_sig)
      raise AssertError, "failed to seriazlie compact signature" unless res == 1

      output.read_bytes(SIZE_COMPACT)
    end

    def ecdsa_deserialize_compact(ser_sig)
      raise ArgumentError, 'invalid signature length' unless ser_sig.size == 64

      raw_sig = C::ECDSASignature.new.pointer

      res = C.secp256k1_ecdsa_signature_parse_compact(@ctx, raw_sig, ser_sig)
      raise AssertError, "failed to deserialize compact signature" unless res == 1

      raw_sig
    end

    ##
    # Check and optionally convert a signature to a normalized lower-S form. If
    # check_only is `true` then the normalized signature is not returned.
    #
    # This function always return a tuple containing a boolean (`true` if not
    # previously normalized or `false` if signature was already normalized),
    # and the normalized signature. When check_only is `true`, the normalized
    # signature returned is always `nil`.
    #
    def ecdsa_signature_normalize(raw_sig, check_only: false)
      sigout = check_only ? nil : C::ECDSASignature.new.pointer
      res = C.secp256k1_ecdsa_signature_normalize(@ctx, sigout, raw_sig)
      [res == 1, sigout]
    end

    def ecdsa_recover(msg, recover_sig, raw: false, digest: Digest::SHA256)
      raise AssertError, 'instance not configured for ecdsa recover' if (@flags & ALL_FLAGS) != ALL_FLAGS

      msg32 = hash32 msg, raw, digest
      pubkey = C::Pubkey.new.pointer

      res = C.secp256k1_ecdsa_recover(@ctx, pubkey, recover_sig, msg32)
      raise AssertError, 'failed to recover ECDSA public key' unless res == 1

      pubkey
    end

    def ecdsa_recoverable_serialize(recover_sig)
      output = FFI::MemoryPointer.new :uchar, SIZE_COMPACT
      recid = FFI::MemoryPointer.new :int

      C.secp256k1_ecdsa_recoverable_signature_serialize_compact(@ctx, output, recid, recover_sig)

      [output.read_bytes(SIZE_COMPACT), recid.read_int]
    end

    def ecdsa_recoverable_deserialize(ser_sig, rec_id)
      raise ArgumentError, 'invalid rec_id' if rec_id < 0 || rec_id > 3
      raise ArgumentError, 'invalid signature length' if ser_sig.size != 64

      recover_sig = C::ECDSARecoverableSignature.new.pointer

      res = C.secp256k1_ecdsa_recoverable_signature_parse_compact(@ctx, recover_sig, ser_sig, rec_id)
      raise AssertError, 'failed to parse ECDSA compact sig' unless res == 1

      recover_sig
    end

    def ecdsa_recoverable_convert(recover_sig)
      normal_sig = C::ECDSASignature.new.pointer
      C.secp256k1_ecdsa_recoverable_signature_convert(@ctx, normal_sig, recover_sig)
      normal_sig
    end

  end
end
