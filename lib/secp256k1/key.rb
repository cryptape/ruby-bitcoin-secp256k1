require 'digest'
require 'securerandom'

module Secp256k1

  class BaseKey
    def initialize(ctx, flags)
      @destroy = false

      unless ctx
        raise ArgumentError, "invalid flags" unless [NO_FLAGS, FLAG_SIGN, FLAG_VERIFY, ALL_FLAGS].include?(flags)
        ctx = C.secp256k1_context_create flags
        @destroy = true
      end

      @flags = flags
      @ctx = ctx

      ObjectSpace.define_finalizer(self) do |id|
        C.secp256k1_context_destroy @ctx if @destroy
      end
    end
  end

  class PublicKey < BaseKey
    include ECDSA, Utils

    attr :public_key

    def initialize(pubkey: nil, raw: false, flags: FLAG_VERIFY, ctx: nil)
      super(ctx, flags)

      if pubkey
        if raw
          raise ArgumentError, 'raw pubkey must be bytes' unless pubkey.instance_of?(String)
          @public_key = deserialize pubkey
        else
          #raise ArgumentError, 'pubkey must be an internal object' unless pubkey.instance_of?(String)
          @public_key = pubkey
        end
      else
        @public_key = nil
      end
    end

    def serialize(compressed: true)
      raise AssertError, 'No public key defined' unless @public_key

      len_compressed = compressed ? 33 : 65
      res_compressed = FFI::MemoryPointer.new :char, len_compressed
      outlen = FFI::MemoryPointer.new(:size_t).write_uint(len_compressed)
      compflag = compressed ? EC_COMPRESSED : EC_UNCOMPRESSED

      res = C.secp256k1_ec_pubkey_serialize(@ctx, res_compressed, outlen, @public_key, compflag)
      raise AssertError, 'pubkey serialization failed' unless res == 1

      res_compressed.read_bytes(len_compressed)
    end

    def deserialize(pubkey_ser)
      raise ArgumentError, 'unknown public key size (expected 33 or 65)' unless [33,65].include?(pubkey_ser.size)

      pubkey = C::Pubkey.new.pointer

      res = C.secp256k1_ec_pubkey_parse(@ctx, pubkey, pubkey_ser, pubkey_ser.size)
      raise AssertError, 'invalid public key' unless res == 1

      @public_key = pubkey
      pubkey
    end

    ##
    # Add a number of public keys together.
    #
    def combine(pubkeys)
      raise ArgumentError, 'must give at least 1 pubkey' if pubkeys.empty?

      outpub = FFI::Pubkey.new.pointer
      #pubkeys.each {|item| }

      res = C.secp256k1_ec_pubkey_combine(@ctx, outpub, pubkeys, pubkeys.size)
      raise AssertError, 'failed to combine public keys' unless res == 1

      @public_key = outpub
      outpub
    end

    ##
    # Tweak the current public key by adding a 32 byte scalar times the
    # generator to it and return a new PublicKey instance.
    #
    def tweak_add(scalar)
      tweak_public :secp256k1_ec_pubkey_tweak_add, scalar
    end

    ##
    # Tweak the current public key by multiplying it by a 32 byte scalar and
    # return a new PublicKey instance.
    #
    def tweak_mul(scalar)
      tweak_public :secp256k1_ec_pubkey_tweak_mul, scalar
    end

    def ecdsa_verify(msg, raw_sig, raw: false, digest: Digest::SHA256)
      raise AssertError, 'No public key defined' unless @public_key
      raise AssertError, 'instance not configured for sig verification' if (@flags & FLAG_VERIFY) != FLAG_VERIFY

      msg32 = hash32 msg, raw, digest

      !!C.secp256k1_ecdsa_verify(@ctx, raw_sig, msg32, @public_key)
    end

    def ecdh(scalar)
      raise AssertError, 'No public key defined' unless @public_key
      raise ArgumentError, 'scalar must be composed of 32 bytes' unless scalar.instance_of?(String) && scalar.size == 32

      result = FFI::MemoryPointer.new :char, 32

      res = C.secp256k1_ecdh @ctx, result, @public_key, scalar
      raise AssertError, "invalid scalar (#{scalar})" unless res == 1

      result.read_bytes(32)
    end

    private

    def tweak_public(meth, scalar)
      raise ArgumentError, 'scalar must be composed of 32 bytes' unless scalar.instance_of?(String) && scalar.size == 32
      raise AssertError, 'No public key defined.' unless @public_key

      newpub = self.class.new serialize, raw: true

      res = C.send meth, newpub.public_key, scalar
      raise AssertError, 'Tweak is out of range' unless res == 1

      newpub
    end

  end

  class PrivateKey < BaseKey
    include ECDSA, Utils

    attr :pubkey

    def initialize(privkey: nil, raw: true, flags: ALL_FLAGS, ctx: nil)
      raise AssertError, "invalid flags" unless [ALL_FLAGS, FLAG_SIGN].include?(flags)

      super(ctx, flags)

      @pubkey = nil
      @private_key = nil

      if privkey
        if raw
          raise ArgumentError, "privkey must be composed of 32 bytes" unless privkey.instance_of?(String) && privkey.size == 32
          set_raw_privkey privkey
        else
          deserialize privkey
        end
      else
        set_raw_privkey generate_private_key
      end
    end

    def ecdsa_sign(msg, raw: false, digest: Digest::SHA256)
      msg32 = hash32 msg, raw, digest
      raw_sig = C::ECDSASignature.new.pointer

      res = C.secp256k1_ecdsa_sign @ctx, raw_sig, msg32, @private_key, nil, nil
      raise AssertError, "failed to sign" unless res == 1

      raw_sig
    end

    def ecdsa_sign_recoverable(msg, raw: false, digest: Digest::SHA256)
      msg32 = hash32 msg, raw, digest
      raw_sig = FFI::MemoryPointer.new :byte, C::ECDSARecoverableSignature, false

      res = C.secp256k1_ecdsa_sign_recoverable @ctx, raw_sig, msg32, @private_key, nil, nil
      raise AssertError, "failed to sign" unless res == 1

      raw_sig
    end

    def set_raw_privkey(privkey)
      raise ArgumentError, "invalid private key" unless C.secp256k1_ec_seckey_verify(@ctx, privkey)
      @private_key = privkey
      update_public_key
    end

    ##
    # Tweak the current private key by adding a 32 bytes scalar to it and
    # return a new raw private key composed of 32 bytes.
    #
    def tweak_add(scalar)
      tweak_private :secp256k1_ec_privkey_tweak_add, scalar
    end

    ##
    # Tweak the current private key by multiplying it by a 32 byte scalar and
    # return a new raw private key composed of 32 bytes.
    #
    def tweak_mul(scalar)
      tweak_private :secp256k1_ec_pubkey_tweak_mul, scalar
    end

    private

    def tweak_private(meth, scalar)
      raise ArgumentError, "scalar must be composed of 32 bytes" unless scalar.instance_of?(String) && scalar.size == 32

      key = FFI::MemoryPointer.new(:uchar, 32).put_string(@private_key)

      C.send meth, @ctx, key, scalar
      raise AssertError, "Tweak is out of range" unless res == 1

      key.read_string(32)
    end

    def update_public_key
      public_key = generate_public_key @private_key
      @pubkey = PublicKey.new pubkey: public_key, raw: false, ctx: @ctx, flags: @flags
    end

    def generate_public_key(privkey)
      pubkey_ptr = C::Pubkey.new.pointer

      res = C.secp256k1_ec_pubkey_create @ctx, pubkey_ptr, privkey
      raise AssertError, "failed to generate public key" unless res == 1

      pubkey_ptr
    end

    def generate_private_key
      SecureRandom.random_bytes(32)
    end

    def serialize
      encode_hex @private_key
    end

    def deserialize(privkey_serialized)
      raise ArgumentError, "invalid private key" unless privkey_serialized.size == 64

      rawkey = decode_hex privkey_serialized
      set_raw_privkey rawkey

      @private_key
    end

  end
end
