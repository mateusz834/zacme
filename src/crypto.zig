const openssl = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl.h");
});

const std = @import("std");
const log = @import("./log.zig");

pub const Key = struct {
    type: Type,
    pkey: ?*openssl.EVP_PKEY,

    pub const Type = union(enum) {
        RSA: u32,
        ECDSA: Curve,
        pub const Curve = enum { P256, P384, P521 };
    };

    pub fn generate(keyType: Type) !Key {
        var pkey = switch (keyType) {
            Type.RSA => |size| try generate_rsa(size),
            Type.ECDSA => |curve| try generate_ecdsa(curve),
        };
        return Key{ .type = keyType, .pkey = pkey };
    }

    pub fn from_pem(data: []const u8) !Key {
        var bio = openssl.BIO_new_mem_buf(&data[0], @intCast(c_int, data.len)) orelse {
            log.err("failed while parsing PEM encoded private key");
            return error.BIONewMemBuf;
        };
        defer _ = openssl.BIO_free(bio);

        var pkey = openssl.PEM_read_bio_PrivateKey(bio, null, null, null) orelse {
            log.err("failed while parsing PEM encoded private key");
            return error.PEMReadBioPrivateKeyFailed;
        };

        switch (openssl.EVP_PKEY_id(pkey)) {
            openssl.EVP_PKEY_RSA => {
                var rsa = openssl.EVP_PKEY_get1_RSA(pkey) orelse {
                    log.err("failed while parsing PEM encoded peivate key");
                    return error.EVPPkeyGet1RSAFailed;
                };
                var bits = openssl.RSA_security_bits(rsa);
                return Key{ .type = .{ .RSA = @intCast(u32, bits) }, .pkey = pkey };
            },
            openssl.EVP_PKEY_EC => {
                return Key{ .type = .{ .RSA = 2048 }, .pkey = pkey };
            },
            else => {
                log.err("unknown private key type in pem file");
                return error.UnknownPrivKey;
            },
        }
    }

    pub fn to_pem(self: *Key, allocator: std.mem.Allocator) ![]u8 {
        _ = allocator;
        _ = self;
    }

    fn generate_rsa(size: u32) !?*openssl.EVP_PKEY {
        // Wrapper for openssl.EVP_RSA_gen(), zig cannot translate that macro.
        // Defined in openssl.c.
        return openssl.gen_RSA(size) orelse {
            log.errf("failed while generating RSA-{} key", .{size});
            return error.RSAKeyGenerationFailure;
        };
    }

    fn generate_ecdsa(curve: Type.Curve) !?*openssl.EVP_PKEY {
        var curve_name = switch (curve) {
            .P256 => "prime256v1",
            .P384 => "secp384r1",
            .P521 => "secp521r1",
        };
        return openssl.gen_ECDSA(curve_name) orelse {
            log.err("failed while generating ECDSA key");
            return error.ECDSAgen;
        };
    }

    pub fn sign(self: *Key, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        if (self.pkey == null) {
            @panic("usage of null private key");
        }

        return switch (self.type) {
            Type.RSA => try sign_rsa(self.pkey.?, allocator, data),
            else => unreachable,
        };
    }

    fn sign_rsa(rsa: *openssl.EVP_PKEY, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        var md_ctx = openssl.EVP_MD_CTX_create() orelse {
            log.err("failed while creating the RSA EVP_MD_CTX");
            return error.EVPDigestSignInitFailed;
        };
        defer openssl.EVP_MD_CTX_free(md_ctx);

        var evp_pkey: ?*openssl.EVP_PKEY_CTX = null;
        var ret = openssl.EVP_DigestSignInit(md_ctx, &evp_pkey, openssl.EVP_sha256(), null, rsa);
        if (ret <= 0) {
            log.err("failed while creating the RSA DigestSign");
            return error.EVPDigestSignInitFailed;
        }

        ret = openssl.EVP_DigestSignUpdate(md_ctx, &data[0], data.len);
        if (ret <= 0) {
            log.err("failed while updating the RSA EVP digest");
            return error.EVPDigestSignUpdateFailed;
        }

        var size: usize = 0;
        ret = openssl.EVP_DigestSignFinal(md_ctx, null, &size);
        if (ret <= 0) {
            log.err("failed while determining the RSA signature size");
            return error.EVPDigestSignFinalFailed;
        }

        var sig = try allocator.alloc(u8, size);
        ret = openssl.EVP_DigestSignFinal(md_ctx, &sig[0], &size);
        if (ret <= 0) {
            log.err("failed while copying the RSA signature");
            return error.EVPDigestSignFinalFailed;
        }

        return sig;
    }
};
