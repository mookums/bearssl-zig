const std = @import("std");

const aead_src = &.{
    "src/aead/ccm.c",
    "src/aead/eax.c",
    "src/aead/gcm.c",
};

const codec_src = &.{
    "src/codec/ccopy.c",
    "src/codec/dec16be.c",
    "src/codec/dec32le.c",
    "src/codec/dec64le.c",
    "src/codec/enc16le.c",
    "src/codec/enc32le.c",
    "src/codec/enc64le.c",
    //"src/codec/pemdec.t0",
    "src/codec/dec16be.c",
    "src/codec/dec32be.c",
    "src/codec/dec64be.c",
    "src/codec/enc16be.c",
    "src/codec/enc32be.c",
    "src/codec/enc64be.c",
    "src/codec/pemdec.c",
    "src/codec/pemenc.c",
};

const ec_src = &.{
    "src/ec/ec_all_m15.c",
    "src/ec/ec_all_m31.c",
    "src/ec/ec_c25519_i15.c",
    "src/ec/ec_c25519_i31.c",
    "src/ec/ec_c25519_m15.c",
    "src/ec/ec_c25519_m31.c",
    "src/ec/ec_curve25519.c",
    "src/ec/ec_default.c",
    "src/ec/ecdsa_atr.c",
    "src/ec/ecdsa_default_sign_asn1.c",
    "src/ec/ecdsa_default_sign_raw.c",
    "src/ec/ecdsa_default_vrfy_asn1.c",
    "src/ec/ecdsa_default_vrfy_raw.c",
    "src/ec/ecdsa_i15_bits.c",
    "src/ec/ecdsa_i15_sign_asn1.c",
    "src/ec/ecdsa_i15_sign_raw.c",
    "src/ec/ecdsa_i15_vrfy_asn1.c",
    "src/ec/ecdsa_i15_vrfy_raw.c",
    "src/ec/ecdsa_i31_bits.c",
    "src/ec/ecdsa_i31_sign_asn1.c",
    "src/ec/ecdsa_i31_sign_raw.c",
    "src/ec/ecdsa_i31_vrfy_asn1.c",
    "src/ec/ecdsa_i31_vrfy_raw.c",
    "src/ec/ecdsa_rta.c",
    "src/ec/ec_keygen.c",
    "src/ec/ec_p256_m15.c",
    "src/ec/ec_p256_m31.c",
    "src/ec/ec_prime_i15.c",
    "src/ec/ec_prime_i31.c",
    "src/ec/ec_pubkey.c",
    "src/ec/ec_secp256r1.c",
    "src/ec/ec_secp384r1.c",
    "src/ec/ec_secp521r1.c",
};

const hash_src = &.{
    "src/hash/dig_oid.c",
    "src/hash/dig_size.c",
    "src/hash/ghash_ctmul32.c",
    "src/hash/ghash_ctmul64.c",
    "src/hash/ghash_ctmul.c",
    "src/hash/ghash_pclmul.c",
    "src/hash/ghash_pwr8.c",
    "src/hash/md5.c",
    "src/hash/md5sha1.c",
    "src/hash/mgf1.c",
    "src/hash/multihash.c",
    "src/hash/sha1.c",
    "src/hash/sha2big.c",
    "src/hash/sha2small.c",
};

const int_src = &.{
    "src/int/i15_add.c",
    "src/int/i15_bitlen.c",
    "src/int/i15_decmod.c",
    "src/int/i15_decode.c",
    "src/int/i15_decred.c",
    "src/int/i15_encode.c",
    "src/int/i15_fmont.c",
    "src/int/i15_iszero.c",
    "src/int/i15_moddiv.c",
    "src/int/i15_modpow2.c",
    "src/int/i15_modpow.c",
    "src/int/i15_montmul.c",
    "src/int/i15_mulacc.c",
    "src/int/i15_muladd.c",
    "src/int/i15_ninv15.c",
    "src/int/i15_reduce.c",
    "src/int/i15_rshift.c",
    "src/int/i15_sub.c",
    "src/int/i15_tmont.c",
    "src/int/i31_add.c",
    "src/int/i31_bitlen.c",
    "src/int/i31_decmod.c",
    "src/int/i31_decode.c",
    "src/int/i31_decred.c",
    "src/int/i31_encode.c",
    "src/int/i31_fmont.c",
    "src/int/i31_iszero.c",
    "src/int/i31_moddiv.c",
    "src/int/i31_modpow2.c",
    "src/int/i31_modpow.c",
    "src/int/i31_montmul.c",
    "src/int/i31_mulacc.c",
    "src/int/i31_muladd.c",
    "src/int/i31_ninv31.c",
    "src/int/i31_reduce.c",
    "src/int/i31_rshift.c",
    "src/int/i31_sub.c",
    "src/int/i31_tmont.c",
    "src/int/i32_add.c",
    "src/int/i32_bitlen.c",
    "src/int/i32_decmod.c",
    "src/int/i32_decode.c",
    "src/int/i32_decred.c",
    "src/int/i32_div32.c",
    "src/int/i32_encode.c",
    "src/int/i32_fmont.c",
    "src/int/i32_iszero.c",
    "src/int/i32_modpow.c",
    "src/int/i32_montmul.c",
    "src/int/i32_mulacc.c",
    "src/int/i32_muladd.c",
    "src/int/i32_ninv32.c",
    "src/int/i32_reduce.c",
    "src/int/i32_sub.c",
    "src/int/i32_tmont.c",
    "src/int/i62_modpow2.c",
};

const kdf_src = &.{
    "src/kdf/hkdf.c",
};

const mac_src = &.{
    "src/mac/hmac.c",
    "src/mac/hmac_ct.c",
};

const rand_src = &.{
    "src/rand/aesctr_drbg.c",
    "src/rand/hmac_drbg.c",
    "src/rand/sysrng.c",
};

const rsa_src = &.{
    "src/rsa/rsa_default_keygen.c",
    "src/rsa/rsa_default_modulus.c",
    "src/rsa/rsa_default_oaep_decrypt.c",
    "src/rsa/rsa_default_oaep_encrypt.c",
    "src/rsa/rsa_default_pkcs1_sign.c",
    "src/rsa/rsa_default_pkcs1_vrfy.c",
    "src/rsa/rsa_default_priv.c",
    "src/rsa/rsa_default_privexp.c",
    "src/rsa/rsa_default_pub.c",
    "src/rsa/rsa_default_pubexp.c",
    "src/rsa/rsa_i15_keygen.c",
    "src/rsa/rsa_i15_modulus.c",
    "src/rsa/rsa_i15_oaep_decrypt.c",
    "src/rsa/rsa_i15_oaep_encrypt.c",
    "src/rsa/rsa_i15_pkcs1_sign.c",
    "src/rsa/rsa_i15_pkcs1_vrfy.c",
    "src/rsa/rsa_i15_priv.c",
    "src/rsa/rsa_i15_privexp.c",
    "src/rsa/rsa_i15_pub.c",
    "src/rsa/rsa_i15_pubexp.c",
    "src/rsa/rsa_i31_keygen.c",
    "src/rsa/rsa_i31_keygen_inner.c",
    "src/rsa/rsa_i31_modulus.c",
    "src/rsa/rsa_i31_oaep_decrypt.c",
    "src/rsa/rsa_i31_oaep_encrypt.c",
    "src/rsa/rsa_i31_pkcs1_sign.c",
    "src/rsa/rsa_i31_pkcs1_vrfy.c",
    "src/rsa/rsa_i31_priv.c",
    "src/rsa/rsa_i31_privexp.c",
    "src/rsa/rsa_i31_pub.c",
    "src/rsa/rsa_i31_pubexp.c",
    "src/rsa/rsa_i32_oaep_decrypt.c",
    "src/rsa/rsa_i32_oaep_encrypt.c",
    "src/rsa/rsa_i32_pkcs1_sign.c",
    "src/rsa/rsa_i32_pkcs1_vrfy.c",
    "src/rsa/rsa_i32_priv.c",
    "src/rsa/rsa_i32_pub.c",
    "src/rsa/rsa_i62_keygen.c",
    "src/rsa/rsa_i62_oaep_decrypt.c",
    "src/rsa/rsa_i62_oaep_encrypt.c",
    "src/rsa/rsa_i62_pkcs1_sign.c",
    "src/rsa/rsa_i62_pkcs1_vrfy.c",
    "src/rsa/rsa_i62_priv.c",
    "src/rsa/rsa_i62_pub.c",
    "src/rsa/rsa_oaep_pad.c",
    "src/rsa/rsa_oaep_unpad.c",
    "src/rsa/rsa_pkcs1_sig_pad.c",
    "src/rsa/rsa_pkcs1_sig_unpad.c",
    "src/rsa/rsa_ssl_decrypt.c",
};

const ssl_src = &.{
    "src/ssl/prf.c",
    "src/ssl/prf_md5sha1.c",
    "src/ssl/prf_sha256.c",
    "src/ssl/prf_sha384.c",
    "src/ssl/ssl_ccert_single_ec.c",
    "src/ssl/ssl_ccert_single_rsa.c",
    "src/ssl/ssl_client.c",
    "src/ssl/ssl_client_default_rsapub.c",
    "src/ssl/ssl_client_full.c",
    "src/ssl/ssl_engine.c",
    "src/ssl/ssl_engine_default_aescbc.c",
    "src/ssl/ssl_engine_default_aesccm.c",
    "src/ssl/ssl_engine_default_aesgcm.c",
    "src/ssl/ssl_engine_default_chapol.c",
    "src/ssl/ssl_engine_default_descbc.c",
    "src/ssl/ssl_engine_default_ec.c",
    "src/ssl/ssl_engine_default_ecdsa.c",
    "src/ssl/ssl_engine_default_rsavrfy.c",
    "src/ssl/ssl_hashes.c",
    "src/ssl/ssl_hs_client.c",
    //"src/ssl/ssl_hs_client.t0",
    //"src/ssl/ssl_hs_common.t0",
    "src/ssl/ssl_hs_server.c",
    //"src/ssl/ssl_hs_server.t0",
    "src/ssl/ssl_io.c",
    "src/ssl/ssl_keyexport.c",
    "src/ssl/ssl_lru.c",
    "src/ssl/ssl_rec_cbc.c",
    "src/ssl/ssl_rec_ccm.c",
    "src/ssl/ssl_rec_chapol.c",
    "src/ssl/ssl_rec_gcm.c",
    "src/ssl/ssl_scert_single_ec.c",
    "src/ssl/ssl_scert_single_rsa.c",
    "src/ssl/ssl_server.c",
    "src/ssl/ssl_server_full_ec.c",
    "src/ssl/ssl_server_full_rsa.c",
    "src/ssl/ssl_server_mine2c.c",
    "src/ssl/ssl_server_mine2g.c",
    "src/ssl/ssl_server_minf2c.c",
    "src/ssl/ssl_server_minf2g.c",
    "src/ssl/ssl_server_minr2g.c",
    "src/ssl/ssl_server_minu2g.c",
    "src/ssl/ssl_server_minv2g.c",
};

const symcipher_src = &.{
    "src/symcipher/aes_big_cbcdec.c",
    "src/symcipher/aes_big_cbcenc.c",
    "src/symcipher/aes_big_ctr.c",
    "src/symcipher/aes_big_ctrcbc.c",
    "src/symcipher/aes_big_dec.c",
    "src/symcipher/aes_big_enc.c",
    "src/symcipher/aes_common.c",
    "src/symcipher/aes_ct64.c",
    "src/symcipher/aes_ct64_cbcdec.c",
    "src/symcipher/aes_ct64_cbcenc.c",
    "src/symcipher/aes_ct64_ctr.c",
    "src/symcipher/aes_ct64_ctrcbc.c",
    "src/symcipher/aes_ct64_dec.c",
    "src/symcipher/aes_ct64_enc.c",
    "src/symcipher/aes_ct.c",
    "src/symcipher/aes_ct_cbcdec.c",
    "src/symcipher/aes_ct_cbcenc.c",
    "src/symcipher/aes_ct_ctr.c",
    "src/symcipher/aes_ct_ctrcbc.c",
    "src/symcipher/aes_ct_dec.c",
    "src/symcipher/aes_ct_enc.c",
    "src/symcipher/aes_pwr8.c",
    "src/symcipher/aes_pwr8_cbcdec.c",
    "src/symcipher/aes_pwr8_cbcenc.c",
    "src/symcipher/aes_pwr8_ctr.c",
    "src/symcipher/aes_pwr8_ctrcbc.c",
    "src/symcipher/aes_small_cbcdec.c",
    "src/symcipher/aes_small_cbcenc.c",
    "src/symcipher/aes_small_ctr.c",
    "src/symcipher/aes_small_ctrcbc.c",
    "src/symcipher/aes_small_dec.c",
    "src/symcipher/aes_small_enc.c",
    "src/symcipher/aes_x86ni.c",
    "src/symcipher/aes_x86ni_cbcdec.c",
    "src/symcipher/aes_x86ni_cbcenc.c",
    "src/symcipher/aes_x86ni_ctr.c",
    "src/symcipher/aes_x86ni_ctrcbc.c",
    "src/symcipher/chacha20_ct.c",
    "src/symcipher/chacha20_sse2.c",
    "src/symcipher/des_ct.c",
    "src/symcipher/des_ct_cbcdec.c",
    "src/symcipher/des_ct_cbcenc.c",
    "src/symcipher/des_support.c",
    "src/symcipher/des_tab.c",
    "src/symcipher/des_tab_cbcdec.c",
    "src/symcipher/des_tab_cbcenc.c",
    "src/symcipher/poly1305_ctmul32.c",
    "src/symcipher/poly1305_ctmul.c",
    "src/symcipher/poly1305_ctmulq.c",
    "src/symcipher/poly1305_i15.c",
};

const x509_src = &.{
    "src/x509/asn1enc.c",
    //"src/x509/asn1.t0",
    "src/x509/encode_ec_pk8der.c",
    "src/x509/encode_ec_rawder.c",
    "src/x509/encode_rsa_pk8der.c",
    "src/x509/encode_rsa_rawder.c",
    "src/x509/skey_decoder.c",
    //"src/x509/skey_decoder.t0",
    "src/x509/x509_decoder.c",
    //"src/x509/x509_decoder.t0",
    "src/x509/x509_knownkey.c",
    "src/x509/x509_minimal.c",
    "src/x509/x509_minimal_full.c",
    //"src/x509/x509_minimal.t0",
};

const MacroPair = struct {
    mode: ?bool,
    macro_name: []const u8,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var macro_list = std.ArrayList(MacroPair).init(b.allocator);
    defer macro_list.deinit();
    {
        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_64",
                "When enabled, 64-bit integers are assumed to be efficient",
            ),
            .macro_name = "BR_64",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_LOWMUL",
                "When enabled, low multiplication of 32 bits are assumed to be efficient",
            ),
            .macro_name = "BR_LOWMUL",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_SLOW_MUL",
                "When enabled, multiplications are assumed to be substationally slow",
            ),
            .macro_name = "BR_SLOW_MUL",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_SLOW_MUL15",
                "When enabled, short multiplications are assumed to be substationally slow",
            ),
            .macro_name = "BR_SLOW_MUL15",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_CT_MUL31",
                "When enabled, multiplications of 31 bit values use an alternate impl",
            ),
            .macro_name = "BR_CT_MUL31",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_CT_MUL15",
                "When enabled, multiplications of 15 bit values use an alternate impl",
            ),
            .macro_name = "BR_CT_MUL15",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_NO_ARITH_SHIFT",
                "When enabled, arithmetic right shifts are slower but avoids implementation-defined behavior",
            ),
            .macro_name = "BR_NO_ARITH_SHIFT",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_RDRAND",
                "When enabled, the SSL engine will use RDRAND opcode to obtain quality randomness",
            ),
            .macro_name = "BR_RDRAND",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_USE_RANDOM",
                "When enabled, the SSL engine will use /dev/urandom to obtain quality randomness",
            ),
            .macro_name = "BR_USE_RANDOM",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_USE_WIN32_RAND",
                "When enabled, the SSL engine will use Win32 (CryptoAPI) to obtain quality randomness",
            ),
            .macro_name = "BR_USE_WIN32_RAND",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_USE_UNIX_TIME",
                "When enabled, the X.509 validation engine uses time() and assumes Unix Epoch",
            ),
            .macro_name = "BR_USE_UNIX_TIME",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_USE_WIN32_TIME",
                "When enabled, the X.509 validation engine uses GetSystemTimeAsFileTime()",
            ),
            .macro_name = "BR_USE_WIN32_TIME",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_ARMEL_CORTEXM_GCC",
                "When enabled, some operations are replaced with inline assembly. Used only when target arch is ARM (thumb), endianness is little, and compiler is GCC or GCC compatible (for inline asm)",
            ),
            .macro_name = "BR_ARMEL_CORTEXM_GCC",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_AES_X86NI",
                "When enabled, the AES implementation using the x86 \"NI\" instructions will be compiled",
            ),
            .macro_name = "BR_AES_X86NI",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_SSE2",
                "When enabled, SSE2 instrinsics will be used for some algorithm implementations",
            ),
            .macro_name = "BR_SSE2",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_POWER8",
                "When enabled, the AES implementation using the POWER ISA 2.07 opcodes is compiled",
            ),
            .macro_name = "BR_POWER8",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_INT128",
                "When enabled, 'unsigned __int64' and 'unsigned __128' types will be used for 64x64->128 mul",
            ),
            .macro_name = "BR_INT128",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_UMUL128",
                "When enabled, '_umul128()' and '_addcarry_u64()' instrincts will be used for 64x64->128 mul",
            ),
            .macro_name = "BR_UMUL128",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_LE_UNALIGNED",
                "When enabled, the current architecture is assumed to use little-endian with little penalty to unaligned access",
            ),
            .macro_name = "BR_LE_UNALIGNED",
        });

        try macro_list.append(.{
            .mode = b.option(
                bool,
                "BR_BE_UNALIGNED",
                "When enabled, the current architecture is assumed to use big-endian with little penalty to unaligned access",
            ),
            .macro_name = "BR_BE_UNALIGNED",
        });
    }

    const bearssl = b.addStaticLibrary(.{
        .name = "bearssl",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    bearssl.addCSourceFile(.{ .file = b.path("src/settings.c") });

    bearssl.addIncludePath(b.path("src/"));
    bearssl.addIncludePath(b.path("inc/"));

    for (macro_list.items) |item| {
        if (item.mode) |mode| {
            bearssl.root_module.addCMacro(
                item.macro_name,
                try std.fmt.allocPrint(b.allocator, "{d}", .{@intFromBool(mode)}),
            );
        }
    }

    const flags = &.{
        "-W",
        "-Wall",
        "-fPIC",
    };

    bearssl.addCSourceFiles(.{ .files = aead_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = codec_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = ec_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = hash_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = int_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = kdf_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = mac_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = rand_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = rsa_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = ssl_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = symcipher_src, .flags = flags });
    bearssl.addCSourceFiles(.{ .files = x509_src, .flags = flags });

    bearssl.installHeadersDirectory(
        b.path("inc/"),
        "",
        .{},
    );

    b.installArtifact(bearssl);
}
