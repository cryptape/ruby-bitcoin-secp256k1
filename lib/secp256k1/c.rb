# -*- encoding : ascii-8bit -*-
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

    # void secp256k1_context_destroy(secp256k1_context* ctx)
    attach_function :secp256k1_context_destroy, [:pointer], :void

    # int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen)
    attach_function :secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int

    # int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey)
    attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int

    # int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags)
    attach_function :secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int

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

    # int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
    attach_function :secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_recover(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32)
    attach_function :secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_verify(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey)
    attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_signature_normalize(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin)
    attach_function :secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context *ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature *sig)
    attach_function :secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int

    # int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context *ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid)
    attach_function :secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int

    # int secp256k1_ecdsa_recoverable_signature_convert(const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const secp256k1_ecdsa_recoverable_signature *sigin)
    attach_function :secp256k1_ecdsa_recoverable_signature_convert, [:pointer, :pointer, :pointer], :int

  end
end
