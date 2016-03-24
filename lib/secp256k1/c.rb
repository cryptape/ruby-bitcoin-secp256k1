require 'ffi'
require 'ffi/tools/const_generator'

module Secp256k1
  module C
    extend FFI::Library

    ffi_lib (ENV['LIBSECP256K1'] || 'libsecp256k1')

    Constants = FFI::ConstGenerator.new('Secp256k1', required: true) do |gen|
      gen.include 'secp256k1.h'

      gen.const(:SECP256K1_EC_COMPRESSED)
      gen.const(:SECP256K1_EC_UNCOMPRESSED)

      gen.const(:SECP256K1_CONTEXT_SIGN)
      gen.const(:SECP256K1_CONTEXT_VERIFY)
      gen.const(:SECP256K1_CONTEXT_NONE)
    end

    class Pubkey < FFI::Struct
      layout :data, [:uchar, 64]
    end

    class ECDSASignature < FFI::Struct
      layout :data, [:uchar, 64]
    end

    class ECDSARecoverableSignature < FFI::Struct
      layout :data, [:uchar, 65]
    end

    # secp256k1_context* secp256k1_context_create(unsigned int flags)
    attach_function :secp256k1_context_create, [:uint], :pointer

    # int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey)
    attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int

    # int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey)
    attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int

    # int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig)
    attach_function :secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig)
    attach_function :secp256k1_ecdsa_signature_serialize_compact, [:pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen)
    attach_function :secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int

    # int secp256k1_ecdsa_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input64)
    attach_function :secp256k1_ecdsa_signature_parse_compact, [:pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
    attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_verify(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey)
    attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int

  end
end
