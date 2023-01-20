const openssl = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/objects.h");
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

            // max_str_size is the max possible length of a string returned by as_str().
            pub const max_str_size = lbl: {
                switch (@typeInfo(Curve)) {
                    .Enum => |enumInfo| {
                        var max = 0;
                        for (enumInfo.fields) |field| {
                            max = @max(max, @intToEnum(Curve, field.value).as_str().len);
                        }
                        break :lbl max;
                    },
                    else => unreachable,
                }
            };

            pub fn as_str(self: Curve) []const u8 {
                return switch (self) {
                    .P256 => "prime256v1",
                    .P384 => "secp384r1",
                    .P521 => "secp521r1",
                };
            }

            pub const FromStrError = error{UnknownCurve};

            pub fn from_str(str: []const u8) FromStrError!Curve {
                if (std.mem.eql(u8, str, Curve.P256.as_str())) {
                    return Curve.P256;
                } else if (std.mem.eql(u8, str, Curve.P384.as_str())) {
                    return Curve.P384;
                } else if (std.mem.eql(u8, str, Curve.P521.as_str())) {
                    return Curve.P521;
                }
                return error.UnknownCurve;
            }

            pub fn signing_hash(self: Curve) ?*const openssl.EVP_MD {
                return switch (self) {
                    .P256 => openssl.EVP_sha256(),
                    .P384 => openssl.EVP_sha384(),
                    .P521 => openssl.EVP_sha512(),
                };
            }

            pub fn size(self: Curve) usize {
                return switch (self) {
                    .P256 => 32,
                    .P384 => 48,
                    .P521 => 66,
                };
            }
        };
    };

    pub fn deinit(self: *Key) void {
        openssl.EVP_PKEY_free(self.pkey.?);
    }

    pub const KeyGenerationError = error{
        RSAKeyGenerationFailure,
        ECDSAKeyGenerationFailure,
    };

    pub fn generate(keyType: Type) KeyGenerationError!Key {
        var pkey = switch (keyType) {
            Type.RSA => |size| try generate_rsa(size),
            Type.ECDSA => |curve| try generate_ecdsa(curve),
        };
        return Key{ .type = keyType, .pkey = pkey };
    }

    fn generate_rsa(size: u32) KeyGenerationError!?*openssl.EVP_PKEY {
        // Wrapper for openssl.EVP_RSA_gen(), zig cannot translate that macro.
        // Defined in openssl.c.
        return openssl.gen_RSA(size) orelse {
            openssl_print_error("failed while generating RSA-{} key", .{size});
            return KeyGenerationError.RSAKeyGenerationFailure;
        };
    }

    fn generate_ecdsa(curve: Type.Curve) KeyGenerationError!?*openssl.EVP_PKEY {
        var curveName = curve.as_str();
        // Wrapper for openssl.EVP_EC_gen(), zig cannot translate that macro.
        // Defined in openssl.c.
        return openssl.gen_ECDSA(curveName.ptr) orelse {
            openssl_print_error("failed while generating ECDSA with curve: '{s}'", .{curveName});
            return KeyGenerationError.ECDSAKeyGenerationFailure;
        };
    }

    pub const PEMParseError = error{
        BioNewMemBufFailure,
        PemReadBioPrivateKeyFailure,
        UnsupportedPrivKeyType,
        EvpPkeyGetBitsFailure,
        UnsupportedECDSACurve,
    } || std.mem.Allocator.Error;

    pub fn from_pem(allocator: std.mem.Allocator, data: []const u8) PEMParseError!Key {
        var bio = openssl.BIO_new_mem_buf(&data[0], @intCast(c_int, data.len)) orelse {
            openssl_print_error("failed while creating in-mem BIO buffer for PEM parsing", .{});
            return PEMParseError.BioNewMemBufFailure;
        };
        defer openssl.BIO_vfree(bio);

        var pkey = openssl.PEM_read_bio_PrivateKey(bio, null, null, null) orelse {
            openssl_print_error("failed while parsing PEM encoded private key", .{});
            return PEMParseError.PemReadBioPrivateKeyFailure;
        };

        var nid = openssl.EVP_PKEY_get_id(pkey);
        return switch (nid) {
            openssl.EVP_PKEY_RSA => try from_pem_rsa(pkey),
            openssl.EVP_PKEY_EC => try from_pem_ecdsa(pkey, allocator),
            else => {
                log.errf("unsupported private key type found inside the pem file: {s}", .{openssl.OBJ_nid2sn(nid)});
                return PEMParseError.UnsupportedPrivKeyType;
            },
        };
    }

    fn from_pem_rsa(pkey: *openssl.EVP_PKEY) PEMParseError!Key {
        var ret = openssl.EVP_PKEY_get_bits(pkey);
        if (ret <= 0) {
            openssl_print_error("failed while determining the RSA bits size", .{});
            return PEMParseError.EvpPkeyGetBitsFailure;
        }
        return Key{ .type = .{ .RSA = @intCast(u32, ret) }, .pkey = pkey };
    }

    fn from_pem_ecdsa(pkey: *openssl.EVP_PKEY, allocator: std.mem.Allocator) PEMParseError!Key {
        var ec_str_buf: [Type.Curve.max_str_size + 1]u8 = undefined;
        var size: usize = 0;

        // EVP_PKEY_get_group_name() returns 1 if the group name could be filled in, otherwise 0.
        // so it means that the buffer was too small to fit the curve name.
        // Allocate a temporary buffer to print a nice error message with the curve name,
        var ret = openssl.EVP_PKEY_get_group_name(pkey, &ec_str_buf[0], ec_str_buf.len, &size);
        if (ret <= 0) {
            size = 0;
            ret = openssl.EVP_PKEY_get_group_name(pkey, null, 0, &size);
            if (ret > 0) {
                var errCurveName = try allocator.alloc(u8, size + 1);
                defer allocator.free(errCurveName);

                size = 0;
                ret = openssl.EVP_PKEY_get_group_name(pkey, &errCurveName[0], errCurveName.len, &size);
                if (ret > 0) {
                    var curveName = errCurveName[0..size];
                    openssl_print_error("unsupported ECDSA private key curve found inside the PEM file: {s}", .{curveName});
                    return PEMParseError.UnsupportedECDSACurve;
                }
            }

            openssl_print_error("unsupported ECDSA private key curve found inside the PEM file", .{});
            return PEMParseError.UnsupportedECDSACurve;
        }

        var curveName = ec_str_buf[0..size];
        var curve = Type.Curve.from_str(curveName) catch |err| switch (err) {
            Type.Curve.FromStrError.UnknownCurve => {
                log.errf("unsupported ECDSA private key curve found inside the PEM file: {s}", .{curveName});
                return PEMParseError.UnsupportedECDSACurve;
            },
        };

        return Key{ .type = .{ .ECDSA = curve }, .pkey = pkey };
    }

    pub const PEMEncodeError = error{
        NewMemBioFailure,
        PemWriteBioPrivateKeyFailure,
    } || std.mem.Allocator.Error;

    pub fn to_pem(self: *Key, allocator: std.mem.Allocator) PEMEncodeError![]u8 {
        var bio = openssl.BIO_new(openssl.BIO_s_mem()) orelse {
            openssl_print_error("falied while creating in-memory BIO", .{});
            return PEMEncodeError.NewMemBioFailure;
        };
        defer openssl.BIO_vfree(bio);

        var ret = openssl.PEM_write_bio_PrivateKey(bio, self.pkey, null, null, 0, null, null);
        if (ret <= 0) {
            openssl_print_error("failed while encoding private key to PEM format", .{});
            return PEMEncodeError.PemWriteBioPrivateKeyFailure;
        }

        var buf: ?[*]u8 = null;
        var len = openssl.BIO_get_mem_data(bio, &buf);

        var pem = try allocator.alloc(u8, @intCast(usize, len));
        std.mem.copy(u8, pem, buf.?[0..@intCast(usize, len)]);
        return pem;
    }

    pub const SignError = error{
        EvpMdCtxCreateFailure,
        EvpDigestSignInitFailure,
        EvpDigestSignUpdateFailure,
        EvpDigestSignFinalFailure,
        EcdsaSigNewFailure,
        d21iEcdsaSigFailure,
        EcdsaSigGet0RFailure,
        EcdsaSigGet0SFailure,
        BnBn2BinpadFailure,
    } || std.mem.Allocator.Error;

    pub fn sign(self: *const Key, allocator: std.mem.Allocator, data: []const u8) SignError![]u8 {
        if (self.pkey == null) {
            @panic("usage of null private key");
        }

        return switch (self.type) {
            Type.RSA => try sign_rsa(self.pkey.?, allocator, data),
            Type.ECDSA => |curve| try sign_ecdsa(self.pkey.?, curve, allocator, data),
        };
    }

    fn sign_rsa(rsa: *openssl.EVP_PKEY, allocator: std.mem.Allocator, data: []const u8) SignError![]u8 {
        return sign_evp(rsa, openssl.EVP_sha256().?, allocator, data);
    }

    fn sign_ecdsa(rsa: *openssl.EVP_PKEY, curve: Type.Curve, allocator: std.mem.Allocator, data: []const u8) SignError![]u8 {
        var sig = try sign_evp(rsa, curve.signing_hash().?, allocator, data);
        defer allocator.free(sig);

        // TODO handle
        var ecsig = openssl.ECDSA_SIG_new(); // orelse {
        //    log.err("failed while creating the ECDSA signature decoding structure");
        //	return SignError.EcdsaSigNewFailure;
        //};
        defer openssl.ECDSA_SIG_free(ecsig);

        // What a mess here ....
        var dataPtr: [1][*c]const u8 = [1][*]const u8{sig.ptr};
        var dataPtr2: [*c][*c]const u8 = dataPtr[0..];
        _ = openssl.d2i_ECDSA_SIG(&ecsig, dataPtr2, @intCast(c_long, sig.len)) orelse {
            openssl_print_error("failed while decoding the DER-encoded ecdsa signature", .{});
            return SignError.d21iEcdsaSigFailure;
        };

        var r = openssl.ECDSA_SIG_get0_r(ecsig) orelse {
            openssl_print_error("failed while getting the ecdsa (r) coordinate", .{});
            return SignError.EcdsaSigGet0RFailure;
        };

        var s = openssl.ECDSA_SIG_get0_s(ecsig) orelse {
            openssl_print_error("failed while getting the ecdsa (s) coordinate", .{});
            return SignError.EcdsaSigGet0SFailure;
        };

        var size = curve.size();
        var jwsSig = try allocator.alloc(u8, size * 2);
        errdefer allocator.free(jwsSig);

        var ret = openssl.BN_bn2binpad(r, &jwsSig[0], @intCast(c_int, size));
        if (ret <= 0) {
            openssl_print_error("failed while getting the ecdsa coordinate (r) from bignum", .{});
            return SignError.BnBn2BinpadFailure;
        }

        ret = openssl.BN_bn2binpad(s, &jwsSig[size], @intCast(c_int, size));
        if (ret <= 0) {
            openssl_print_error("failed while getting the ecdsa coordinate (s) from bignum", .{});
            return SignError.BnBn2BinpadFailure;
        }

        return jwsSig;
    }

    fn sign_evp(key: *openssl.EVP_PKEY, hash: *const openssl.EVP_MD, allocator: std.mem.Allocator, data: []const u8) SignError![]u8 {
        var md_ctx = openssl.EVP_MD_CTX_create() orelse {
            openssl_print_error("failed while creating EVP_MD_CTX", .{});
            return SignError.EvpMdCtxCreateFailure;
        };
        defer openssl.EVP_MD_CTX_free(md_ctx);

        var evp_pkey: ?*openssl.EVP_PKEY_CTX = null;
        var ret = openssl.EVP_DigestSignInit(md_ctx, &evp_pkey, hash, null, key);
        if (ret <= 0) {
            openssl_print_error("failed while initializing the digest signer", .{});
            return SignError.EvpDigestSignInitFailure;
        }

        ret = openssl.EVP_DigestSignUpdate(md_ctx, &data[0], data.len);
        if (ret <= 0) {
            openssl_print_error("failed while updating the signature digest", .{});
            return SignError.EvpDigestSignUpdateFailure;
        }

        var size: usize = 0;
        ret = openssl.EVP_DigestSignFinal(md_ctx, null, &size);
        if (ret <= 0) {
            openssl_print_error("failed while determining the final signature size", .{});
            return SignError.EvpDigestSignFinalFailure;
        }

        var sig = try allocator.alloc(u8, size);
        errdefer allocator.free(sig);

        ret = openssl.EVP_DigestSignFinal(md_ctx, &sig[0], &size);
        if (ret <= 0) {
            openssl_print_error("failed while copying the final signature", .{});
            return SignError.EvpDigestSignFinalFailure;
        }

        return sig;
    }

    fn openssl_print_error(comptime fmt: []const u8, args: anytype) void {
        var opensslError = false;
        while (true) {
            var e = openssl.ERR_get_error();
            if (e == 0)
                break;

            opensslError = true;
            var stderr = std.io.getStdErr().writer();
            stderr.print("Error: " ++ fmt, args) catch return;
            stderr.print(": {s}\n", .{openssl.ERR_error_string(e, null)}) catch return;
        }

        if (!opensslError) {
            log.errf(fmt, args);
        }
    }
};

const test_allocator = std.testing.allocator;

test "rsa-2048" {
    try testKey(.{ .RSA = 2048 });
}

test "ecdsa-P256" {
    _ = try testKey(.{ .ECDSA = .P256 });
}

test "ecdsa-P384" {
    _ = try testKey(.{ .ECDSA = .P384 });
}

test "ecdsa-P521" {
    _ = try testKey(.{ .ECDSA = .P521 });
}

fn testKey(keyType: Key.Type) !void {
    var key = try Key.generate(keyType);
    defer key.deinit();
    try std.testing.expectEqual(keyType, key.type);

    var keyPem = try key.to_pem(test_allocator);
    defer test_allocator.free(keyPem);
    var keyFromPEM = try Key.from_pem(test_allocator, keyPem);
    defer keyFromPEM.deinit();

    try std.testing.expectEqual(keyFromPEM.type, key.type);

    const signData = "sign data";
    var sign = try key.sign(test_allocator, signData);
    defer test_allocator.free(sign);
    var sign2 = try keyFromPEM.sign(test_allocator, signData);
    defer test_allocator.free(sign2);

    try testVerifySignature(key, signData, sign);
    try testVerifySignature(key, signData, sign2);
    try testVerifySignature(keyFromPEM, signData, sign);
    try testVerifySignature(keyFromPEM, signData, sign2);
}

fn testVerifySignature(key: Key, data: []const u8, signature: []const u8) !void {
    var buf: [1024 * 8]u8 = undefined;
    var sig = switch (key.type) {
        .RSA => signature,
        .ECDSA => blk: {
            var sigLen = signature.len;
            if (sigLen % 2 != 0) {
                return error.SignatureVerifyFailed;
            }
            var r = signature[0..(sigLen / 2)];
            var s = signature[(sigLen / 2)..];

            var sig = openssl.ECDSA_SIG_new();
            defer openssl.ECDSA_SIG_free(sig);
            _ = openssl.ECDSA_SIG_set0(sig, openssl.BN_bin2bn(&r[0], @intCast(c_int, r.len), null), openssl.BN_bin2bn(&s[0], @intCast(c_int, s.len), null));

            var len = openssl.i2d_ECDSA_SIG(sig, null);
            var sign = buf[0..@intCast(usize, len)];

            // What a mess here ....
            var dataPtr: [1][*c]u8 = [1][*]u8{sign.ptr};
            var dataPtr2: [*c][*c]u8 = dataPtr[0..];
            _ = openssl.i2d_ECDSA_SIG(sig, dataPtr2);
            break :blk sign;
        },
    };

    var md_ctx = openssl.EVP_MD_CTX_create() orelse {
        return error.SignatureVerifyFailed;
    };
    defer openssl.EVP_MD_CTX_free(md_ctx);

    var hash = switch (key.type) {
        .RSA => openssl.EVP_sha256(),
        .ECDSA => |curve| switch (curve) {
            .P256 => openssl.EVP_sha256(),
            .P384 => openssl.EVP_sha384(),
            .P521 => openssl.EVP_sha512(),
        },
    };

    if (openssl.EVP_DigestVerifyInit(md_ctx, null, hash, null, key.pkey) <= 0) {
        return error.SignatureVerifyFailed;
    }

    if (openssl.EVP_DigestVerifyUpdate(md_ctx, &data[0], data.len) <= 0) {
        return error.SignatureVerifyFailed;
    }

    if (openssl.EVP_DigestVerifyFinal(md_ctx, &sig[0], sig.len) <= 0) {
        return error.SignatureVerifyFailed;
    }
}
