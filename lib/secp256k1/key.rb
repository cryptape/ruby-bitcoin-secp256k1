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
  end

  class PrivateKey < BaseKey
    include ECDSA, Utils

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
      @pubkey = PublicKey.new public_key, raw: false, ctx: @ctx, flags: @flags
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

    def seriazlie
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
