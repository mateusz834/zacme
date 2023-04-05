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
        .ED25519, .ED448 => "EdDSA",
    };
}

fn jwkCurveName(curve: crypto.Key.Type.Curve) []const u8 {
    return switch (curve) {
        .P256 => "P-256",
        .P384 => "P-384",
        .P521 => "P-521",
    };
}

const UrlSafeNoPadBase64JsonEncoder = struct {
    data: []const u8,

    pub fn jsonStringify(self: @This(), options: std.json.StringifyOptions, out_stream: anytype) !void {
        var data = self.data;

        const max_process_bytes = 330;
        // Must be div by 3 for correct padding
        std.debug.assert(max_process_bytes % 3 == 0);

        var base64_out_buf: [(max_process_bytes / 3) * 4]u8 = undefined;

        try out_stream.writeByte('\"');
        while (data.len != 0) {
            const process_len = @min(data.len, max_process_bytes);
            try std.json.encodeJsonStringChars(base64Encoder.encode(&base64_out_buf, data[0..process_len]), options, out_stream);
            data = data[process_len..];
        }
        try out_stream.writeByte('\"');
    }
};

pub const JWK = struct {
    public_key: *const crypto.Key.PublicKey,

    pub fn jsonStringify(self: JWK, options: std.json.StringifyOptions, out_stream: anytype) !void {
        switch (self.public_key.*) {
            .RSA => |val| {
                return std.json.stringify(.{
                    .e = UrlSafeNoPadBase64JsonEncoder{ .data = val.E },
                    .kty = "RSA",
                    .n = UrlSafeNoPadBase64JsonEncoder{ .data = val.N },
                }, options, out_stream);
            },
            .ECDSA => |ec| switch (ec) {
                inline else => |val, ecdsa| {
                    return std.json.stringify(.{
                        .crv = jwkCurveName(ecdsa),
                        .kty = "EC",
                        .x = UrlSafeNoPadBase64JsonEncoder{ .data = &val.X },
                        .y = UrlSafeNoPadBase64JsonEncoder{ .data = &val.Y },
                    }, options, out_stream);
                },
            },
            .ED25519 => |val| {
                return std.json.stringify(.{
                    .crv = "Ed25519",
                    .kty = "OKP",
                    .x = UrlSafeNoPadBase64JsonEncoder{ .data = &val.X },
                }, options, out_stream);
            },
            .ED448 => |val| {
                return std.json.stringify(.{
                    .crv = "Ed448",
                    .kty = "OKP",
                    .x = UrlSafeNoPadBase64JsonEncoder{ .data = &val.X },
                }, options, out_stream);
            },
        }
    }
};

// This test proves that the std.json.stringify procuces a valid JWK for use for JWK Thumbprint.
// It must not contain amy spaces and the fields must be in specifed order.

// RFC 7638 3: Construct a JSON object [RFC7159] containing only the required
// members of a JWK representing the key and with no whitespace or
// line breaks before or after any syntactic elements and with the
// required members ordered lexicographically by the Unicode
// [UNICODE] code points of the member names.  (This JSON object is
// itself a legal JWK representation of the key.)
//
// RFC 7638 3.3: The required members in the input to the hash function are ordered
// lexicographically by the Unicode code points of the member names.
test "JWK valid for JWK Tumbprint" {
    const testValue1 = "t" ** 32;
    const testValue2 = "a" ** 57;
    const b64TestValue1 = try encodeBase64(std.testing.allocator, testValue1);
    defer std.testing.allocator.free(b64TestValue1);
    const b64TestValue2 = try encodeBase64(std.testing.allocator, testValue2);
    defer std.testing.allocator.free(b64TestValue2);

    var jwkRSA = JWK{ .public_key = &crypto.Key.PublicKey{ .RSA = .{ .E = testValue1, .N = testValue2 } } };
    var jwkECDSA = JWK{ .public_key = &crypto.Key.PublicKey{ .ECDSA = .{ .P256 = .{ .X = testValue1[0..32].*, .Y = testValue1[0..32].* } } } };
    var jwkED2519 = JWK{ .public_key = &crypto.Key.PublicKey{ .ED25519 = .{ .X = testValue1[0..32].* } } };
    var jwkED448 = JWK{ .public_key = &crypto.Key.PublicKey{ .ED448 = .{ .X = testValue2[0..57].* } } };

    var rsa = try std.json.stringifyAlloc(std.testing.allocator, jwkRSA, .{});
    defer std.testing.allocator.free(rsa);

    var ecdsa = try std.json.stringifyAlloc(std.testing.allocator, &jwkECDSA, .{});
    defer std.testing.allocator.free(ecdsa);

    var ed25519 = try std.json.stringifyAlloc(std.testing.allocator, &jwkED2519, .{});
    defer std.testing.allocator.free(ed25519);

    var ed448 = try std.json.stringifyAlloc(std.testing.allocator, &jwkED448, .{});
    defer std.testing.allocator.free(ed448);

    try std.testing.expectFmt(
        rsa,
        "{s}\"e\":\"{s}\",\"kty\":\"{s}\",\"n\":\"{s}\"{s}",
        .{ "{", b64TestValue1, "RSA", b64TestValue2, "}" },
    );

    try std.testing.expectFmt(
        ecdsa,
        "{s}\"crv\":\"{s}\",\"kty\":\"{s}\",\"x\":\"{s}\",\"y\":\"{s}\"{s}",
        .{ "{", "P-256", "EC", b64TestValue1, b64TestValue1, "}" },
    );

    try std.testing.expectFmt(
        ed25519,
        "{s}\"crv\":\"{s}\",\"kty\":\"{s}\",\"x\":\"{s}\"{s}",
        .{ "{", "Ed25519", "OKP", b64TestValue1, "}" },
    );

    try std.testing.expectFmt(
        ed448,
        "{s}\"crv\":\"{s}\",\"kty\":\"{s}\",\"x\":\"{s}\"{s}",
        .{ "{", "Ed448", "OKP", b64TestValue2, "}" },
    );
}

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
    var public = try key.getPublicKey(allocator);
    defer public.deinit(allocator);
    return jws(allocator, key, payload, .{
        .alg = jwsAlgName(key),
        .nonce = nonce,
        .url = url,
        .jwk = .{ .public_key = &public },
    });
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

    var sign = try key.sign(allocator, signData, false);
    defer allocator.free(sign);

    return try std.json.stringifyAlloc(allocator, .{
        .protected = headersBase64,
        .payload = payloadBase64,
        .signature = UrlSafeNoPadBase64JsonEncoder{ .data = sign },
    }, .{});
}
