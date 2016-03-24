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

    # int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
    attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

#    # secp256k1_context_t* secp256k1_context_create(int flags)
#    attach_function :secp256k1_context_create, [:int], :pointer
#
#    # secp256k1_context_t* secp256k1_context_clone(const secp256k1_context_t* ctx)
#    attach_function :secp256k1_context_clone, [:pointer], :pointer
#
#    # void secp256k1_context_destroy(secp256k1_context_t* ctx)
#    attach_function :secp256k1_context_destroy, [:pointer], :void
#
#    # int secp256k1_ecdsa_verify(const secp256k1_context_t* ctx, const unsigned char *msg32, const unsigned char *sig, int siglen, const unsigned char *pubkey, int pubkeylen)
#    attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :int, :pointer, :int], :int
#
#    # int secp256k1_ecdsa_sign(const secp256k1_context_t* ctx, const unsigned char *msg32, unsigned char *sig, int *siglen, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata)
#    attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ecdsa_sign_compact(const secp256k1_context_t* ctx, const unsigned char *msg32, unsigned char *sig64, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata, int *recid)
#    attach_function :secp256k1_ecdsa_sign_compact, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ecdsa_recover_compact(const secp256k1_context_t* ctx, const unsigned char *msg32, const unsigned char *sig64, unsigned char *pubkey, int *pubkeylen, int compressed, int recid)
#    attach_function :secp256k1_ecdsa_recover_compact, [:pointer, :pointer, :pointer, :pointer, :pointer, :int, :int], :int
#
#    # int secp256k1_ec_seckey_verify(const secp256k1_context_t* ctx, const unsigned char *seckey)
#    attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int
#
#    # int secp256k1_ec_pubkey_verify(const secp256k1_context_t* ctx, const unsigned char *pubkey, int pubkeylen)
#    attach_function :secp256k1_ec_pubkey_verify, [:pointer, :pointer, :int], :int
#
#    # int secp256k1_ec_pubkey_create(const secp256k1_context_t* ctx, unsigned char *pubkey, int *pubkeylen, const unsigned char *seckey, int compressed)
#    attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer, :pointer, :int], :int
#
#    # int secp256k1_ec_pubkey_decompress(const secp256k1_context_t* ctx, unsigned char *pubkey, int *pubkeylen)
#    attach_function :secp256k1_ec_pubkey_decompress, [:pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ec_privkey_export(const secp256k1_context_t* ctx, const unsigned char *seckey, unsigned char *privkey, int *privkeylen, int compressed)
#    attach_function :secp256k1_ec_privkey_export, [:pointer, :pointer, :pointer, :pointer, :int], :int
#
#    # int secp256k1_ec_privkey_import(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *privkey, int privkeylen)
#    attach_function :secp256k1_ec_privkey_import, [:pointer, :pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ec_privkey_tweak_add(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *tweak)
#    attach_function :secp256k1_ec_privkey_tweak_add, [:pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ec_pubkey_tweak_add(const secp256k1_context_t* ctx, unsigned char *pubkey, int pubkeylen, const unsigned char *tweak)
#    attach_function :secp256k1_ec_pubkey_tweak_add, [:pointer, :pointer, :int, :pointer], :int
#
#    # int secp256k1_ec_privkey_tweak_mul(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *tweak)
#    attach_function :secp256k1_ec_privkey_tweak_mul, [:pointer, :pointer, :pointer], :int
#
#    # int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context_t* ctx, unsigned char *pubkey, int pubkeylen, const unsigned char *tweak)
#    attach_function :secp256k1_ec_pubkey_tweak_mul, [:pointer, :pointer, :int, :pointer], :int
#
#    # int secp256k1_context_randomize(secp256k1_context_t* ctx, const unsigned char *seed32)
#    attach_function :secp256k1_context_randomize, [:pointer, :pointer], :int

  end
end
