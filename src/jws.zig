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

const headers = struct {
    alg: []const u8,
    nonce: []const u8,
    url: []const u8,
    jwk: ?[]const u8 = null,
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

pub fn withJWK(allocator: std.mem.Allocator, key: crypto.Key, payload: anytype, nonce: []const u8, url: []const u8) ![]const u8 {
    return jws(allocator, key, payload, headers{
        .alg = jwsAlgName(key),
        .nonce = nonce,
        .url = url,
    });
}

const base64Encoder = std.base64.url_safe_no_pad.Encoder;

fn jws(allocator: std.mem.Allocator, key: crypto.Key, payload: anytype, hdrs: headers) ![]const u8 {
    var jsonHeaders = try std.json.stringifyAlloc(allocator, hdrs, .{});
    defer allocator.free(jsonHeaders);

    var jsonPayload = try std.json.stringifyAlloc(allocator, payload, .{});
    defer allocator.free(jsonPayload);

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

    _ = base64Encoder.encode(signatureBase64, sign);

    const jwsWebSignature = struct {
        protected: []const u8,
        payload: []const u8,
        signature: []const u8,
    };

    return try std.json.stringifyAlloc(allocator, jwsWebSignature{
        .protected = headersBase64,
        .payload = payloadBase64,
        .signature = signatureBase64,
    }, .{});
}
