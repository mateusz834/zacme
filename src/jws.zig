const crypto = @import("./crypto.zig");
const std = @import("std");

fn jwsAlgName(key: crypto.Key) []const u8 {
    return switch (key.type) {
        .RSA => "RS256",
        .ECDSA => |curve| switch (curve) {
            .P256 => "ES256",
            .P384 => "ES384",
            .P521 => "ES521",
        },
    };
}

fn jwkCurveName(curve: crypto.Key.Type.Curve) []const u8 {
    return switch (curve) {
        .P256 => "P-256",
        .P384 => "P-384",
        .P521 => "P-521",
    };
}

pub const JWK = union(enum) {
    RSA: struct { E: []const u8, N: []const u8 },
    ECDSA: struct { Curve: []const u8, X: []const u8, Y: []const u8 },

    pub fn jsonStringify(
        self: JWK,
        options: std.json.StringifyOptions,
        out_stream: anytype,
    ) @TypeOf(out_stream).Error!void {
        switch (self) {
            .RSA => |val| {
                const rsa = struct {
                    e: []const u8,
                    kty: []const u8 = "RSA",
                    n: []const u8,
                };
                return std.json.stringify(rsa{
                    .e = val.E,
                    .n = val.N,
                }, options, out_stream);
            },
            .ECDSA => |val| {
                const ecdsa = struct {
                    crv: []const u8,
                    kty: []const u8 = "EC",
                    x: []const u8,
                    y: []const u8,
                };
                return std.json.stringify(ecdsa{
                    .crv = val.Curve,
                    .x = val.X,
                    .y = val.Y,
                }, options, out_stream);
            },
        }
    }

    pub fn deinit(self: JWK, allocator: std.mem.Allocator) void {
        switch (self) {
            .RSA => |rsa| {
                allocator.free(rsa.E);
                allocator.free(rsa.N);
            },
            .ECDSA => |ecdsa| {
                allocator.free(ecdsa.X);
                allocator.free(ecdsa.Y);
            },
        }
    }

    pub fn fromCryptoPublicKey(allocator: std.mem.Allocator, public: crypto.Key.PublicKey) !JWK {
        switch (public) {
            .RSA => |rsa| {
                var e = try encodeBase64(allocator, rsa.E);
                errdefer allocator.free(e);
                var n = try encodeBase64(allocator, rsa.N);
                errdefer allocator.free(n);
                return .{ .RSA = .{ .E = e, .N = n } };
            },
            .ECDSA => |ecdsa| {
                var x = try encodeBase64(allocator, ecdsa.X);
                errdefer allocator.free(x);
                var y = try encodeBase64(allocator, ecdsa.Y);
                errdefer allocator.free(y);
                return .{ .ECDSA = .{ .Curve = jwkCurveName(ecdsa.Curve), .X = x, .Y = y } };
            },
        }
    }
};

const headers = struct {
    alg: []const u8,
    nonce: ?[]const u8,
    url: []const u8,
    jwk: ?JWK = null,
    kid: ?[]const u8 = null,
};

pub fn withKID(allocator: std.mem.Allocator, key: crypto.Key, payload: anytype, nonce: []const u8, url: []const u8, kid: []const u8) ![]const u8 {
    return jws(allocator, key, payload, headers{
        .alg = jwsAlgName(key),
        .nonce = nonce,
        .url = url,
        .kid = kid,
    });
}

pub fn withJWK(allocator: std.mem.Allocator, key: crypto.Key, payload: anytype, nonce: ?[]const u8, url: []const u8) ![]const u8 {
    var hdrs = headers{
        .alg = jwsAlgName(key),
        .nonce = nonce,
        .url = url,
    };

    var public = try key.getPublicKey(allocator);
    defer public.deinit(allocator);

    hdrs.jwk = try JWK.fromCryptoPublicKey(allocator, public);
    defer hdrs.jwk.?.deinit(allocator);

    return jws(allocator, key, payload, hdrs);
}

const base64Encoder = std.base64.url_safe_no_pad.Encoder;

fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var buf = try allocator.alloc(u8, base64Encoder.calcSize(data.len));
    return base64Encoder.encode(buf, data);
}

fn jws(allocator: std.mem.Allocator, key: crypto.Key, payload: anytype, hdrs: headers) ![]const u8 {
    var jsonHeaders = try std.json.stringifyAlloc(allocator, hdrs, .{ .emit_null_optional_fields = false });
    defer allocator.free(jsonHeaders);

    var jsonPayload: []const u8 = if (@TypeOf(payload) != []const u8) blk: {
        break :blk try std.json.stringifyAlloc(allocator, payload, .{});
    } else blk: {
        break :blk payload;
    };

    defer if (@TypeOf(payload) != []const u8) allocator.free(jsonPayload);

    var sizeJsonHeadersAsBase64 = base64Encoder.calcSize(jsonHeaders.len);
    var sizeJsonPayloadAsBase64 = base64Encoder.calcSize(jsonPayload.len);

    var signData = try allocator.alloc(u8, sizeJsonHeadersAsBase64 + sizeJsonPayloadAsBase64 + 1);
    defer allocator.free(signData);

    var headersBase64 = base64Encoder.encode(signData[0..sizeJsonHeadersAsBase64], jsonHeaders);
    signData[sizeJsonHeadersAsBase64] = '.';
    var payloadBase64 = base64Encoder.encode(signData[sizeJsonHeadersAsBase64 + 1 ..], jsonPayload);

    var sign = try key.sign(allocator, signData);
    defer allocator.free(sign);

    var signatureBase64 = try allocator.alloc(u8, base64Encoder.calcSize(sign.len));
    defer allocator.free(signatureBase64);

    const jwsWebSignature = struct {
        protected: []const u8,
        payload: []const u8,
        signature: []const u8,
    };

    return try std.json.stringifyAlloc(allocator, jwsWebSignature{
        .protected = headersBase64,
        .payload = payloadBase64,
        .signature = base64Encoder.encode(signatureBase64, sign),
    }, .{});
}
