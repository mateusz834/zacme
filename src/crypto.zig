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

        pub const Curve = enum {
            P256,
            P384,
            P521,

            // TODO: comptime
            pub const max_str_size = 10;

            pub fn as_str(self: *const Curve) []const u8 {
                return switch (self.*) {
                    .P256 => "prime256v1",
                    .P384 => "secp384r1",
                    .P521 => "secp521r1",
                };
            }

            pub fn from_str(str: []const u8) !Curve {
                if (std.mem.eql(u8, str, "prime256v1")) {
                    return Curve.P256;
                }
                if (std.mem.eql(u8, str, "secp384r1")) {
                    return Curve.P384;
                }
                if (std.mem.eql(u8, str, "secp521r1")) {
                    return Curve.P521;
                }
                return error.UnknownECCurve;
            }

            pub fn signing_hash(self: *const Curve) ?*const openssl.EVP_MD {
                return switch (self.*) {
                    .P256 => openssl.EVP_sha256(),
                    .P384 => openssl.EVP_sha384(),
                    .P521 => openssl.EVP_sha512(),
                };
            }
            pub fn size(self: *const Curve) usize {
                return switch (self.*) {
                    .P256 => 32,
                    .P384 => 48,
                    .P521 => 66,
                };
            }
        };
    };

    pub fn deinit(self: *Key) !Key {
        openssl.EVP_PKEY_free(self.pkey.?);
    }

    pub fn generate(keyType: Type) !Key {
        var pkey = switch (keyType) {
            Type.RSA => |size| try generate_rsa(size),
            Type.ECDSA => |curve| try generate_ecdsa(curve),
        };
        return Key{ .type = keyType, .pkey = pkey };
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

        // Wrapper for openssl.EVP_EC_gen(), zig cannot translate that macro.
        // Defined in openssl.c.
        return openssl.gen_ECDSA(curve_name) orelse {
            log.err("failed while generating ECDSA key");
            return error.ECDSAgen;
        };
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

        return switch (openssl.EVP_PKEY_get_id(pkey)) {
            openssl.EVP_PKEY_RSA => try from_pem_rsa(pkey),
            openssl.EVP_PKEY_EC => try from_pem_ecdsa(pkey),
            else => {
                log.err("unknown private key type found inside the pem file");
                return error.UnknownPrivKey;
            },
        };
    }

    fn from_pem_rsa(pkey: *openssl.EVP_PKEY) !Key {
        var rsa = openssl.EVP_PKEY_get1_RSA(pkey) orelse {
            log.err("failed while parsing PEM encoded RSA private key");
            return error.EVPPkeyGet1RSAFailed;
        };
        var bits = openssl.RSA_bits(rsa);
        return Key{ .type = .{ .RSA = @intCast(u32, bits) }, .pkey = pkey };
    }

    fn from_pem_ecdsa(pkey: *openssl.EVP_PKEY) !Key {
        var ec_str_buf: [Type.Curve.max_str_size:0]u8 = undefined;
        var size: usize = 0;
        var ret = openssl.EVP_PKEY_get_group_name(pkey, &ec_str_buf[0], ec_str_buf.len, &size);
        if (ret <= 0) {
            log.err("unknown private key curve found inside the pem file");
            return error.UnknownECCurve;
        }
        var curve = try Type.Curve.from_str(ec_str_buf[0..size]);
        return Key{ .type = .{ .ECDSA = curve }, .pkey = pkey };
    }

    pub fn to_pem(self: *Key, allocator: std.mem.Allocator) ![]u8 {
        var bio = openssl.BIO_new(openssl.BIO_s_mem()) orelse {
            log.err("falied while creating in-memory BIO");
            return error.PEM_write_bio_PrivateKeyFailure;
        };
        defer openssl.BIO_vfree(bio);

        var ret = openssl.PEM_write_bio_PrivateKey(bio, self.pkey, null, null, 0, null, null);
        if (ret <= 0) {
            log.err("failed while encoding to PEM");
            return error.PEM_write_bio_PrivateKeyFailure;
        }

        var buf: ?[*]u8 = null;
        var len = openssl.BIO_get_mem_data(bio, &buf);

        var pem = try allocator.alloc(u8, @intCast(usize, len));
        std.mem.copy(u8, pem, buf.?[0..@intCast(usize, len)]);
        return pem;
    }

    pub fn sign(self: *Key, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        if (self.pkey == null) {
            @panic("usage of null private key");
        }

        return switch (self.type) {
            Type.RSA => try sign_rsa(self.pkey.?, allocator, data),
            Type.ECDSA => |curve| try sign_ecdsa(self.pkey.?, curve, allocator, data),
        };
    }

    fn sign_rsa(rsa: *openssl.EVP_PKEY, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
		return sign_evp(rsa,openssl.EVP_sha256().?, allocator, data);
    }

    fn sign_ecdsa(rsa: *openssl.EVP_PKEY, curve: Type.Curve, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
		var sig = try sign_evp(rsa, curve.signing_hash().?, allocator, data);
        defer allocator.free(sig);

        var ecsig = openssl.ECDSA_SIG_new();
        defer openssl.ECDSA_SIG_free(ecsig);

        // What a mess here ....
        var dataPtr: [1][*c]const u8 = [1][*]const u8{sig.ptr};
        var dataPtr2: [*c][*c]const u8 = dataPtr[0..];
        ecsig = openssl.d2i_ECDSA_SIG(&ecsig, dataPtr2, @intCast(c_long, sig.len));
        var r = openssl.ECDSA_SIG_get0_r(ecsig);
        var s = openssl.ECDSA_SIG_get0_s(ecsig);

        var csize = curve.size();

        var jwsSig = try allocator.alloc(u8, csize * 2);
        _ = openssl.BN_bn2binpad(r, &jwsSig[0], @intCast(c_int, csize));
        _ = openssl.BN_bn2binpad(s, &jwsSig[csize], @intCast(c_int, csize));

        return jwsSig;
    }

    fn sign_evp(key: *openssl.EVP_PKEY, hash: *const openssl.EVP_MD, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        var md_ctx = openssl.EVP_MD_CTX_create() orelse {
            log.err("failed while creating the EVP_MD_CTX");
            return error.EVPDigestSignInitFailed;
        };
        defer openssl.EVP_MD_CTX_free(md_ctx);

        var evp_pkey: ?*openssl.EVP_PKEY_CTX = null;
        var ret = openssl.EVP_DigestSignInit(md_ctx, &evp_pkey, hash, null, key);
        if (ret <= 0) {
            log.err("failed while creating the DigestSign");
            return error.EVPDigestSignInitFailed;
        }

        ret = openssl.EVP_DigestSignUpdate(md_ctx, &data[0], data.len);
        if (ret <= 0) {
            log.err("failed while updating the EVP digest");
            return error.EVPDigestSignUpdateFailed;
        }

        var size: usize = 0;
        ret = openssl.EVP_DigestSignFinal(md_ctx, null, &size);
        if (ret <= 0) {
            log.err("failed while determining the signature size");
            return error.EVPDigestSignFinalFailed;
        }

        var sig = try allocator.alloc(u8, size);

        ret = openssl.EVP_DigestSignFinal(md_ctx, &sig[0], &size);
        if (ret <= 0) {
            log.err("failed while copying the signature");
            return error.EVPDigestSignFinalFailed;
        }

		return sig;
	}
};
