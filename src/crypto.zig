const openssl = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/objects.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/asn1t.h");
    @cInclude("openssl.h");
});

// TODO: ed25519 + ed448

const std = @import("std");
const log = @import("./log.zig");
const builtin = @import("builtin");

const derBuilder = struct {
    list: std.ArrayList(u8),
    depth: if (builtin.mode == .Debug) usize else u0 = 0,

    pub const Prefixed = struct {
        startLen: usize,
    };

    pub fn newPrefixed(self: *derBuilder, tag: u8) !Prefixed {
        if (builtin.mode == .Debug) self.depth += 1;

        try self.list.appendSlice(&[_]u8{ tag, 0 });
        return .{ .startLen = self.list.items.len };
    }

    pub fn endPrefixed(self: *derBuilder, p: Prefixed) !void {
        if (builtin.mode == .Debug) self.depth -= 1;

        const endLen = self.list.items.len;
        var len = endLen - p.startLen;
        if (len < 0b10000000) {
            self.list.items[p.startLen - 1] = @intCast(u8, len);
        } else {
            var lenBytes: u8 = if (len > std.math.maxInt(u24)) @panic("value too big") else if (len > std.math.maxInt(u16)) 3 else if (len > std.math.maxInt(u8)) 2 else 1;
            try self.list.appendNTimes(undefined, lenBytes);
            std.mem.copyBackwards(u8, self.list.items[p.startLen + lenBytes ..], self.list.items[p.startLen..endLen]);

            self.list.items[p.startLen - 1] = 0b10000000 | lenBytes;

            var len_bytes = self.list.items[p.startLen .. p.startLen + lenBytes];
            var i: isize = @intCast(isize, len_bytes.len) - 1;
            while (i >= 0) {
                len_bytes[@intCast(usize, i)] = @truncate(u8, len);
                len >>= 8;
                i -= 1;
            }
        }
    }

    pub fn deinit(self: *derBuilder) void {
        if (builtin.mode == .Debug and self.depth != 0) @panic("deinit() called on derBuilder when depth != 0");
        self.list.deinit();
    }
};

test "der builder small length" {
    var builder = derBuilder{ .list = std.ArrayList(u8).init(std.testing.allocator) };
    defer builder.deinit();

    var prefixed = try builder.newPrefixed(10);
    try builder.list.append(1);
    try builder.list.append(1);
    try builder.list.append(1);

    var prefixed2 = try builder.newPrefixed(12);
    try builder.list.append(1);
    try builder.endPrefixed(prefixed2);

    try builder.endPrefixed(prefixed);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 6, 1, 1, 1, 12, 1, 1 }, builder.list.items);
}

test "der builder big length" {
    var builder = derBuilder{ .list = std.ArrayList(u8).init(std.testing.allocator) };
    defer builder.deinit();

    var content = "aa" ** 120;

    var prefixed = try builder.newPrefixed(10);
    try builder.list.appendSlice(content);
    try builder.list.appendSlice(content);

    var prefixed2 = try builder.newPrefixed(12);
    try builder.list.appendSlice(content);
    try builder.endPrefixed(prefixed2);

    try builder.endPrefixed(prefixed);

    var expect = [_]u8{ 10, 0b10000010, 0x02, 0xD3 } ++ content ++ content ++ [_]u8{ 12, 0b10000001, 240 } ++ content;

    try std.testing.expectEqualSlices(u8, expect, builder.list.items);
}

// buildCSR builds a DER-encoded CSR as defined in RFC 2986.
pub fn buildCSR(allocator: std.mem.Allocator, key: *Key, cn: []const u8, dns_sans: ?[][]const u8) ![]const u8 {
    // CommonName has a size limit (1..64) (RFC 5280).
    if (cn.len < 1) return error.CommonNameTooShort;
    if (cn.len > 64) return error.CommonNameTooLong;

    var public = try key.getPublicKey(allocator);
    defer public.deinit(allocator);

    var builder = derBuilder{ .list = std.ArrayList(u8).init(allocator) };
    defer builder.deinit();
    errdefer builder.depth = 0;

    const sequence: u8 = 0x30;
    const set: u8 = 0x31;
    const oid: u8 = 0x06;
    const utf8string: u8 = 0x0C;
    const bitstring: u8 = 0x03;
    const null_tag: u8 = 0x05;
    const integer: u8 = 0x02;
    const octetstring: u8 = 0x04;

    var certifcateRequest = try builder.newPrefixed(sequence);
    {
        var certifcateRequestInfo = try builder.newPrefixed(sequence);
        {
            // version:
            try builder.list.append(integer);
            try builder.list.append(1);
            try builder.list.append(0);

            // subject:
            var rdn_sequence = try builder.newPrefixed(sequence);
            var relative_distinguished_name = try builder.newPrefixed(set);
            var attribute_type_and_value = try builder.newPrefixed(sequence);
            {
                // Type: OID: 2.5.4.3 (commonName).
                const common_name_OID = [_]u8{ 85, 4, 3 };
                try builder.list.append(oid);
                try builder.list.append(@intCast(u8, common_name_OID.len));
                try builder.list.appendSlice(&common_name_OID);

                // Value:
                // TODO: printableString? think about it.
                try builder.list.append(utf8string);
                try builder.list.append(@intCast(u8, cn.len));
                try builder.list.appendSlice(cn);
            }
            try builder.endPrefixed(attribute_type_and_value);
            try builder.endPrefixed(relative_distinguished_name);
            try builder.endPrefixed(rdn_sequence);

            // subjectPKInfo:
            var subject_public_key_info = try builder.newPrefixed(sequence);
            {
                // Algorithm identifier:
                var algorithm_identifer = try builder.newPrefixed(sequence);
                switch (public) {
                    .RSA => {
                        // Algorithm OID:
                        const rsa_OID = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
                        try builder.list.append(oid);
                        try builder.list.append(@intCast(u8, rsa_OID.len));
                        try builder.list.appendSlice(&rsa_OID);

                        // Algorithm parameters (RSA requires NULL):
                        try builder.list.append(null_tag);
                        try builder.list.append(0);
                    },
                    .ECDSA => |ecdsa| {
                        // Algorithm OID:
                        const ecdsa_OID = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
                        try builder.list.append(oid);
                        try builder.list.append(@intCast(u8, ecdsa_OID.len));
                        try builder.list.appendSlice(&ecdsa_OID);

                        // Algorithm parameters (named curve):
                        try builder.list.append(oid);
                        switch (ecdsa.Curve) {
                            .P256 => {
                                var p256_OID = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
                                try builder.list.append(@intCast(u8, p256_OID.len));
                                try builder.list.appendSlice(&p256_OID);
                            },
                            .P384 => {
                                var p384_OID = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
                                try builder.list.append(@intCast(u8, p384_OID.len));
                                try builder.list.appendSlice(&p384_OID);
                            },
                            .P521 => {
                                var p521_OID = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x23 };
                                try builder.list.append(@intCast(u8, p521_OID.len));
                                try builder.list.appendSlice(&p521_OID);
                            },
                        }
                    },
                }
                try builder.endPrefixed(algorithm_identifer);

                // Public key:
                var public_key = try builder.newPrefixed(bitstring);
                try builder.list.append(0); // Number of unused bits prefix.
                {
                    switch (public) {
                        .RSA => |rsa| {
                            var rsa_sequence = try builder.newPrefixed(sequence);
                            {
                                // modulus:
                                var modulus = try builder.newPrefixed(integer);
                                // prepend zero, so it is not intepreted as negative number.
                                if (rsa.N[0] & 0b10000000 != 0) try builder.list.append(0);
                                try builder.list.appendSlice(rsa.N);
                                try builder.endPrefixed(modulus);

                                // exponent:
                                var exponent = try builder.newPrefixed(integer);
                                // prepend zero, so it is not intepreted as negative number.
                                if (rsa.E[0] & 0b10000000 != 0) try builder.list.append(0);
                                try builder.list.appendSlice(rsa.E);
                                try builder.endPrefixed(exponent);
                            }
                            try builder.endPrefixed(rsa_sequence);
                        },
                        .ECDSA => |ecdsa| {
                            // RFC 5480 2.2:
                            // ECPoint ::= OCTET STRING
                            // Implementations of Elliptic Curve Cryptography according to this
                            // document MUST support the uncompressed form and MAY support the
                            // compressed form of the ECC public key.
                            //
                            // The first octet of the OCTET STRING indicates whether the key is
                            // compressed or uncompressed.  The uncompressed form is indicated
                            // by 0x04

                            try builder.list.append(0x04); // uncompressed form
                            // x and y coordinates are already padded with zeros.
                            try builder.list.appendSlice(ecdsa.X);
                            try builder.list.appendSlice(ecdsa.Y);
                        },
                    }
                }
                try builder.endPrefixed(public_key);
            }
            try builder.endPrefixed(subject_public_key_info);

            // Attributes:
            // Context-specific class + constructed bit.
            const attributes_tag: u8 = 0b10100000;
            var attributes = try builder.newPrefixed(attributes_tag);
            if (dns_sans != null) {
                var attribute = try builder.newPrefixed(sequence);
                {
                    // Attribute type:
                    const extention_request_OID = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E };
                    try builder.list.append(oid);
                    try builder.list.append(@intCast(u8, extention_request_OID.len));
                    try builder.list.appendSlice(&extention_request_OID);

                    // Attribute Value:
                    var attribute_values = try builder.newPrefixed(set);
                    {
                        // RFC 2985 5.4.2:
                        // extensionRequest ATTRIBUTE ::= {
                        //        WITH SYNTAX ExtensionRequest
                        //        SINGLE VALUE TRUE
                        //        ID pkcs-9-at-extensionRequest
                        // }
                        // ExtensionRequest ::= Extensions
                        //
                        // RFC 5280:
                        // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
                        // Extension  ::=  SEQUENCE  {
                        //      extnID      OBJECT IDENTIFIER,
                        //      critical    BOOLEAN DEFAULT FALSE,
                        //      extnValue   OCTET STRING
                        //                  -- contains the DER encoding of an ASN.1 value
                        //                  -- corresponding to the extension type identified
                        //                  -- by extnID
                        //      }
                        //
                        // Yeah I don't understand it too. ASN.1 is awesome!!

                        var attribute_value = try builder.newPrefixed(sequence); // Sequence Of
                        {
                            if (dns_sans) |sans| {
                                var requested_extension = try builder.newPrefixed(sequence);
                                {
                                    // extnID:
                                    const subject_alt_name_OID = [_]u8{ 0x55, 0x1D, 0x11 };
                                    try builder.list.append(oid);
                                    try builder.list.append(@intCast(u8, subject_alt_name_OID.len));
                                    try builder.list.appendSlice(&subject_alt_name_OID);

                                    // extnValue:
                                    var extension_value = try builder.newPrefixed(octetstring);
                                    {
                                        var general_names = try builder.newPrefixed(sequence);
                                        {
                                            // RFC 5280 4.2.1.6:
                                            // When the subjectAltName extension contains a domain name system
                                            // label, the domain name MUST be stored in the dNSName (an IA5String).
                                            // The name MUST be in the "preferred name syntax", as specified by
                                            // Section 3.5 of [RFC1034] and as modified by Section 2.1 of
                                            // [RFC1123].
                                            // In  addition, while the string " " is a legal domain name, subjectAltName
                                            // extensions with a dNSName of " " MUST NOT be used.

                                            // Context-specific class + 2.
                                            const dns_name_tag: u8 = 0b10000000 | 2;
                                            for (sans) |dns| {
                                                if (!isValidHostname(dns)) return error.InvalidHostname;
                                                var dns_name = try builder.newPrefixed(dns_name_tag);
                                                try builder.list.appendSlice(dns);
                                                try builder.endPrefixed(dns_name);
                                            }
                                        }
                                        try builder.endPrefixed(general_names);
                                    }
                                    try builder.endPrefixed(extension_value);
                                }
                                try builder.endPrefixed(requested_extension);
                            }
                        }
                        try builder.endPrefixed(attribute_value);
                    }
                    try builder.endPrefixed(attribute_values);
                }
                try builder.endPrefixed(attribute);
            }
            try builder.endPrefixed(attributes);
        }
        try builder.endPrefixed(certifcateRequestInfo);
    }

    var certification_request_info_bytes = builder.list.items[certifcateRequest.startLen..];
    var signature = try key.sign(allocator, certification_request_info_bytes, true);
    defer allocator.free(signature);

    var algorithm_identifier = try builder.newPrefixed(sequence);
    {
        switch (public) {
            .RSA => {
                const sha256WithRSA_OID = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
                try builder.list.append(oid);
                try builder.list.append(@intCast(u8, sha256WithRSA_OID.len));
                try builder.list.appendSlice(&sha256WithRSA_OID);

                // Algorithm parameters (RSA requires NULL):
                try builder.list.append(null_tag);
                try builder.list.append(0);
            },
            .ECDSA => |ecdsa| {
                try builder.list.append(oid);
                switch (ecdsa.Curve) {
                    .P256 => {
                        var ec_sha256_OID = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
                        try builder.list.append(@intCast(u8, ec_sha256_OID.len));
                        try builder.list.appendSlice(&ec_sha256_OID);
                    },
                    .P384 => {
                        var ec_sha384_OID = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
                        try builder.list.append(@intCast(u8, ec_sha384_OID.len));
                        try builder.list.appendSlice(&ec_sha384_OID);
                    },
                    .P521 => {
                        var ec_sha512_OID = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 };
                        try builder.list.append(@intCast(u8, ec_sha512_OID.len));
                        try builder.list.appendSlice(&ec_sha512_OID);
                    },
                }
                // RFC 5758 3.2:
                // When the ecdsa-with-SHA224, ecdsa-with-SHA256, ecdsa-with-SHA384, or
                // ecdsa-with-SHA512 algorithm identifier appears in the algorithm field
                // as an AlgorithmIdentifier, the encoding MUST omit the parameters
                // field.
            },
        }
    }
    try builder.endPrefixed(algorithm_identifier);

    var signature_bitstring = try builder.newPrefixed(bitstring);
    {
        try builder.list.append(0); // Number of unused bits prefix.
        try builder.list.appendSlice(signature);
    }
    try builder.endPrefixed(signature_bitstring);

    try builder.endPrefixed(certifcateRequest);

    return builder.list.toOwnedSlice();
}

// isValidHostname reports whether the hostname is a valid hostname as
// defined in RFC 1034 3.5. Preferred name syntax, but disallows " " as a valid hostname
// and allows letter or digit as a first character in the label (RFC 1123 2.1).
fn isValidHostname(hostname: []const u8) bool {
    if (hostname.len == 0)
        return false;

    if (hostname[hostname.len - 1] == '.') return false;

    if (hostname.len > 253) return false;

    var label_start: usize = 0;
    for (hostname, 0..) |char, i| {
        if (char == '.') {
            if (i == 0 or hostname[i - 1] == '-') return false;

            const len = i - label_start;
            if (len == 0 or len > 63) return false;

            label_start = i + 1;
            continue;
        }

        if (i == label_start) {
            if (!std.ascii.isAlphanumeric(char)) return false;
        } else {
            if (!(std.ascii.isAlphanumeric(char) or char == '-')) return false;
        }

        if (hostname.len - 1 == i) {
            if (hostname[i] == '-') return false;
            const len = (i - label_start) + 1;
            if (len == 0 or len > 63) return false;
            break;
        }
    }

    return true;
}

test "isValidHostname" {
    try std.testing.expect(!isValidHostname(""));
    try std.testing.expect(!isValidHostname(" "));

    try std.testing.expect(isValidHostname("9"));
    try std.testing.expect(!isValidHostname("-"));

    try std.testing.expect(isValidHostname("m"));
    try std.testing.expect(isValidHostname("com"));
    try std.testing.expect(isValidHostname("example.com"));
    try std.testing.expect(isValidHostname("hello.example.com"));
    try std.testing.expect(isValidHostname("h0l1o.example.com"));
    try std.testing.expect(isValidHostname("ha0-o.example.com"));
    try std.testing.expect(isValidHostname("hel-o.example.com"));
    try std.testing.expect(isValidHostname("h-l-o.example.com"));
    try std.testing.expect(isValidHostname("hello9.example.com"));
    try std.testing.expect(isValidHostname("hello.e-xample.com"));

    try std.testing.expect(isValidHostname("a.example.com"));

    try std.testing.expect(isValidHostname("1.example.com"));
    try std.testing.expect(isValidHostname("1hello.example.com"));
    try std.testing.expect(isValidHostname("9hello.example.com"));
    try std.testing.expect(!isValidHostname("-hello.example.com"));

    try std.testing.expect(!isValidHostname(".example.com"));
    try std.testing.expect(!isValidHostname("..example.com"));
    try std.testing.expect(!isValidHostname("hello..example.com"));
    try std.testing.expect(!isValidHostname("hello...example.com"));
    try std.testing.expect(!isValidHostname("hello.example..com"));

    try std.testing.expect(isValidHostname(("a" ** 63) ++ ".example.com"));
    try std.testing.expect(!isValidHostname(("a" ** 64) ++ ".example.com"));

    try std.testing.expect(isValidHostname(((("a" ** 63) ++ ".") ** 3) ++ ("b" ** 49) ++ ".example.com"));
    try std.testing.expect(!isValidHostname(((("a" ** 63) ++ ".") ** 3) ++ ("b" ** 50) ++ ".example.com"));

    try std.testing.expect(!isValidHostname("example.com-"));
    try std.testing.expect(isValidHostname("example.9om"));

    try std.testing.expect(isValidHostname("example.sth." ++ ((("a" ** 63) ++ ".") ** 3) ++ ("b" ** 49)));
    try std.testing.expect(!isValidHostname("example.sth." ++ ((("a" ** 63) ++ ".") ** 3) ++ ("b" ** 50)));

    try std.testing.expect(!isValidHostname("."));
}

test "buildCSR RSA-2048" {
    var key = try Key.generate(.{ .RSA = 2048 });
    defer key.deinit();
    try testCSRWithKey(&key);
}

test "buildCSR ECDSA-P256" {
    var key = try Key.generate(.{ .ECDSA = .P256 });
    defer key.deinit();
    try testCSRWithKey(&key);
}

test "buildCSR ECDSA-P384" {
    var key = try Key.generate(.{ .ECDSA = .P384 });
    defer key.deinit();
    try testCSRWithKey(&key);
}

test "buildCSR ECDSA-P521" {
    var key = try Key.generate(.{ .ECDSA = .P521 });
    defer key.deinit();
    try testCSRWithKey(&key);
}

fn testCSRWithKey(key: *Key) !void {
    var csr = try buildCSR(std.testing.allocator, key, "example.com", null);
    defer std.testing.allocator.free(csr);
    try validateCSR(csr);

    var sans = [_][]const u8{ "example.com", "www.example.com" };
    var csr_with_sans = try buildCSR(std.testing.allocator, key, "example.com", &sans);
    defer std.testing.allocator.free(csr_with_sans);
    try validateCSR(csr_with_sans);

    var sans2 = [_][]const u8{"-s.example.com"};
    try std.testing.expectError(error.InvalidHostname, buildCSR(std.testing.allocator, key, "example.com", &sans2));
}

fn validateCSR(csr: []const u8) !void {
    var dataPtr: [1][*c]const u8 = [1][*]const u8{csr.ptr};
    var dataPtr2: [*c][*c]const u8 = dataPtr[0..];

    var req = openssl.d2i_X509_REQ(null, dataPtr2, @intCast(c_long, csr.len)) orelse return error.DerParseFailure;
    defer openssl.X509_REQ_free(req);

    errdefer openssl_print_error("s", .{});
    var pkey = openssl.X509_REQ_get_pubkey(req) orelse return error.PubKeyExtractFailure;
    if (openssl.X509_REQ_verify(req, pkey) <= 0) return error.SignatureVerifyFailure;
}

pub const StreamingSha256 = struct {
    md_ctx: *openssl.EVP_MD_CTX,

    pub fn init() !StreamingSha256 {
        var md_ctx = openssl.EVP_MD_CTX_new() orelse return error.OutOfMemory;
        errdefer openssl.EVP_MD_CTX_free(md_ctx);

        if (openssl.EVP_DigestInit(md_ctx, openssl.EVP_sha256()) != 1)
            return error.DigestInitFailure;

        return .{ .md_ctx = md_ctx };
    }

    pub fn deinit(self: StreamingSha256) void {
        openssl.EVP_MD_CTX_free(self.md_ctx);
    }

    pub fn writer(self: StreamingSha256) std.io.Writer(StreamingSha256, error{DigestUpdateFailure}, write) {
        return .{ .context = self };
    }

    fn write(context: StreamingSha256, bytes: []const u8) error{DigestUpdateFailure}!usize {
        if (openssl.EVP_DigestUpdate(context.md_ctx, &bytes[0], bytes.len) != 1)
            return error.DigestUpdateFailure;
        return bytes.len;
    }

    pub const digestLength = std.crypto.hash.sha2.Sha256.digest_length;
    pub fn final(self: StreamingSha256) ![digestLength]u8 {
        var md_value: [openssl.EVP_MAX_MD_SIZE]u8 = undefined;
        var len: c_uint = 0;

        if (openssl.EVP_DigestFinal(self.md_ctx, &md_value[0], &len) != 1)
            return error.DigestFinalFailure;

        if (len != digestLength) @panic("openssl internal error, sha256 returned invalid digest length");
        return md_value[0..digestLength].*;
    }
};

test "StreamingSha256" {
    var zigCrypto = std.crypto.hash.sha2.Sha256.init(.{});
    var sha256 = try StreamingSha256.init();
    defer sha256.deinit();

    for (1..100) |i| {
        try sha256.writer().writeByte(@intCast(u8, i));
        try zigCrypto.writer().writeByte(@intCast(u8, i));
    }

    try std.testing.expectEqualSlices(
        u8,
        &zigCrypto.finalResult(),
        &try sha256.final(),
    );
}

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

    pub fn sign(self: *const Key, allocator: std.mem.Allocator, data: []const u8, ecdsa_asn1: bool) SignError![]u8 {
        if (self.pkey == null) {
            @panic("usage of null private key");
        }

        return switch (self.type) {
            Type.RSA => try sign_rsa(self.pkey.?, allocator, data),
            Type.ECDSA => |curve| try sign_ecdsa(self.pkey.?, curve, allocator, data, ecdsa_asn1),
        };
    }

    fn sign_rsa(rsa: *openssl.EVP_PKEY, allocator: std.mem.Allocator, data: []const u8) SignError![]u8 {
        return sign_evp(rsa, openssl.EVP_sha256().?, allocator, data);
    }

    fn sign_ecdsa(rsa: *openssl.EVP_PKEY, curve: Type.Curve, allocator: std.mem.Allocator, data: []const u8, asn1_format: bool) SignError![]u8 {
        var sig = try sign_evp(rsa, curve.signing_hash().?, allocator, data);
        if (asn1_format) return sig;
        defer allocator.free(sig);

        // Extracting r and s from the DER encoded signature.
        // Assuming that the encoding is a valid DER.

        // The biggest supported curve is P521, so the length is < 255B.
        const inner = if (sig[1] & 0b10000000 != 0) sig[3..] else sig[2..];

        // the coordinate is at most 66B so it will fit inside the 1B length encoding.
        var r = inner[2 .. 2 + inner[1]];
        var s = inner[4 + r.len ..];

        // Ignore first byte if zero. Zero might be added, so that it is not intepreted as negative.
        if (r.len > 0 and r[0] == 0) r = r[1..];
        if (s.len > 0 and s[0] == 0) s = s[1..];

        var size = curve.size();
        var jws_sig = try allocator.alloc(u8, size * 2);
        errdefer allocator.free(jws_sig);

        var rsig = jws_sig[0..size];
        std.mem.set(u8, rsig[0 .. size - r.len], 0);
        std.mem.copy(u8, rsig[size - r.len ..], r);

        var ssig = jws_sig[size..];
        std.mem.set(u8, ssig[0 .. size - s.len], 0);
        std.mem.copy(u8, ssig[size - s.len ..], s);

        return jws_sig;
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

        var list = try std.ArrayList(u8).initCapacity(allocator, size);
        list.expandToCapacity();
        errdefer list.deinit();

        ret = openssl.EVP_DigestSignFinal(md_ctx, &list.items[0], &size);
        if (ret <= 0) {
            openssl_print_error("failed while copying the final signature", .{});
            return SignError.EvpDigestSignFinalFailure;
        }

        try list.resize(size);
        return list.toOwnedSlice();
    }

    pub const PublicKey = union(enum) {
        RSA: struct { E: []const u8, N: []const u8 },
        ECDSA: struct { Curve: Type.Curve, X: []const u8, Y: []const u8 },

        pub fn deinit(self: *PublicKey, allocator: std.mem.Allocator) void {
            switch (self.*) {
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
    };

    pub fn getPublicKey(self: *const Key, allocator: std.mem.Allocator) !PublicKey {
        switch (self.type) {
            .RSA => {
                var e = try evp_pkey_get_bignum_param(allocator, self.pkey, openssl.OSSL_PKEY_PARAM_RSA_E);
                errdefer allocator.free(e);
                var n = try evp_pkey_get_bignum_param(allocator, self.pkey, openssl.OSSL_PKEY_PARAM_RSA_N);
                return .{ .RSA = .{ .E = e, .N = n } };
            },
            .ECDSA => |curve| {
                var size = curve.size();
                var x = try evp_pkey_get_bignum_param_padded(allocator, self.pkey, openssl.OSSL_PKEY_PARAM_EC_PUB_X, size);
                errdefer allocator.free(x);
                var y = try evp_pkey_get_bignum_param_padded(allocator, self.pkey, openssl.OSSL_PKEY_PARAM_EC_PUB_Y, size);
                return .{ .ECDSA = .{ .Curve = curve, .X = x, .Y = y } };
            },
        }
    }

    fn evp_pkey_get_bignum_param_padded(allocator: std.mem.Allocator, pkey: ?*openssl.EVP_PKEY, param: [*c]const u8, size: usize) ![]const u8 {
        var bn: ?*openssl.BIGNUM = null;

        var ret = openssl.EVP_PKEY_get_bn_param(pkey, param, &bn);
        if (ret <= 0) {
            openssl_print_error("failed while retreiving the bignum parameter from key", .{});
            return error.EvpPkeyGetBnParamFailure;
        }
        defer openssl.BN_free(bn);

        var bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);

        ret = openssl.BN_bn2binpad(bn, &bytes[0], @intCast(c_int, bytes.len));
        if (ret <= 0) {
            openssl_print_error("failed while retreiving the bignum parameter from key", .{});
            return error.Bn2BinPadFailure;
        }

        return bytes;
    }

    fn evp_pkey_get_bignum_param(allocator: std.mem.Allocator, pkey: ?*openssl.EVP_PKEY, param: [*c]const u8) ![]const u8 {
        var bn: ?*openssl.BIGNUM = null;

        var ret = openssl.EVP_PKEY_get_bn_param(pkey, param, &bn);
        if (ret <= 0) {
            openssl_print_error("failed while retreiving the bignum parameter from key", .{});
            return error.EvpPkeyGetBnParamFailure;
        }
        defer openssl.BN_free(bn);

        var bytes = try allocator.alloc(u8, @intCast(usize, openssl.BN_num_bytes(bn)));
        errdefer allocator.free(bytes);

        ret = openssl.BN_bn2bin(bn, &bytes[0]);
        if (ret <= 0) {
            openssl_print_error("failed while retreiving the bignum parameter from key", .{});
            return error.Bn2BinFailure;
        }

        return bytes;
    }
};

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

const test_allocator = std.testing.allocator;

test "rsa-2048" {
    try testKey(.{ .RSA = 2048 });
}

test "ecdsa-P256" {
    try testKey(.{ .ECDSA = .P256 });
}

test "ecdsa-P384" {
    try testKey(.{ .ECDSA = .P384 });
}

test "ecdsa-P521" {
    try testKey(.{ .ECDSA = .P521 });
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
    var sign = try key.sign(test_allocator, signData, false);
    defer test_allocator.free(sign);
    var sign2 = try keyFromPEM.sign(test_allocator, signData, false);
    defer test_allocator.free(sign2);

    try testVerifySignature(key, signData, sign);
    try testVerifySignature(key, signData, sign2);
    try testVerifySignature(keyFromPEM, signData, sign);
    try testVerifySignature(keyFromPEM, signData, sign2);

    var pub_key = try key.getPublicKey(test_allocator);
    defer pub_key.deinit(test_allocator);

    var pub2_key = try keyFromPEM.getPublicKey(test_allocator);
    defer pub2_key.deinit(test_allocator);

    try verifySignatureFromPublicKey(pub_key, signData, sign);
    try verifySignatureFromPublicKey(pub_key, signData, sign2);
    try verifySignatureFromPublicKey(pub2_key, signData, sign);
    try verifySignatureFromPublicKey(pub2_key, signData, sign2);

    try verifySignatureFromPublicKeyWithZigCrypto(pub_key, signData, sign);
    try verifySignatureFromPublicKeyWithZigCrypto(pub_key, signData, sign2);
    try verifySignatureFromPublicKeyWithZigCrypto(pub2_key, signData, sign);
    try verifySignatureFromPublicKeyWithZigCrypto(pub2_key, signData, sign2);
}

fn verifySignatureFromPublicKeyWithZigCrypto(public: Key.PublicKey, data: []const u8, sig: []const u8) !void {
    switch (public) {
        .ECDSA => |ecdsa| {
            switch (ecdsa.Curve) {
                inline .P256, .P384 => |ecCurve| {
                    const ecc = switch (ecCurve) {
                        .P256 => std.crypto.ecc.P256,
                        .P384 => std.crypto.ecc.P384,
                        else => unreachable,
                    };

                    const ecdsaAlg = switch (ecCurve) {
                        .P256 => std.crypto.sign.ecdsa.EcdsaP256Sha256,
                        .P384 => std.crypto.sign.ecdsa.EcdsaP384Sha384,
                        else => unreachable,
                    };

                    var p = ecdsaAlg.PublicKey{ .p = try ecc.fromAffineCoordinates(.{
                        .x = try ecc.Fe.fromBytes(ecdsa.X[0..ecc.Fe.encoded_length].*, .Big),
                        .y = try ecc.Fe.fromBytes(ecdsa.Y[0..ecc.Fe.encoded_length].*, .Big),
                    }) };

                    var signature = ecdsaAlg.Signature.fromBytes(sig[0..ecdsaAlg.Signature.encoded_length].*);
                    try signature.verify(data, p);
                },
                else => {},
            }
        },
        else => {},
    }
}

fn verifySignatureFromPublicKey(public: Key.PublicKey, data: []const u8, sig: []const u8) !void {
    //const OSSL_PARAM_END = blk: {
    //	var tmp: openssl.OSSL_PARAM = undefined;
    //	tmp.key = null;
    //	break :blk tmp;
    //};

    switch (public) {
        .RSA => |rsa| {
            var bn_e = openssl.BN_bin2bn(&rsa.E[0], @intCast(c_int, rsa.E.len), null) orelse return error.Failed;
            defer openssl.BN_free(bn_e);
            var bn_n = openssl.BN_bin2bn(&rsa.N[0], @intCast(c_int, rsa.N.len), null) orelse return error.Failed;
            defer openssl.BN_free(bn_n);

            var rsa_key = openssl.RSA_new();
            if (openssl.RSA_set0_key(rsa_key, bn_n, bn_e, null) <= 0)
                return error.SignatureVerifyFailed;

            var pkey = openssl.EVP_PKEY_new() orelse return error.Failed;
            defer openssl.EVP_PKEY_free(pkey);

            if (openssl.EVP_PKEY_set1_RSA(pkey, rsa_key) <= 0)
                return error.Failed;

            try testVerifySignature(Key{ .type = .{ .RSA = 0 }, .pkey = pkey }, data, sig);

            //TODO: figure a way to do this without using a deprecated API.
            //TODO: this below does not work.

            //var ctx = openssl.EVP_PKEY_CTX_new_from_name(null, "RSA", null) orelse return error.Failed;
            //defer openssl.EVP_PKEY_CTX_free(ctx);
            //var params =  [_]openssl.OSSL_PARAM{
            //	.{
            //		.key = openssl.OSSL_PKEY_PARAM_RSA_E,
            //		.data_type = openssl.OSSL_PARAM_UNSIGNED_INTEGER,
            //		.data = bn_e,
            //		.data_size = @intCast(usize, openssl.BN_num_bytes(bn_e)),
            //		.return_size = openssl.OSSL_PARAM_UNMODIFIED
            //	},
            //	.{
            //		.key = openssl.OSSL_PKEY_PARAM_RSA_N,
            //		.data_type = openssl.OSSL_PARAM_UNSIGNED_INTEGER,
            //		.data = bn_n,
            //		.data_size = @intCast(usize, openssl.BN_num_bytes(bn_n)),
            //		.return_size = openssl.OSSL_PARAM_UNMODIFIED
            //	},
            //	.{
            //		.key = openssl.OSSL_PKEY_PARAM_RSA_D,
            //		.data_type = openssl.OSSL_PARAM_UNSIGNED_INTEGER,
            //		.data = null,
            //		.data_size = 0,
            //		.return_size = openssl.OSSL_PARAM_UNMODIFIED
            //	},
            //	OSSL_PARAM_END
            //};

            //if (openssl.EVP_PKEY_fromdata_init(ctx) <= 0)
            //	return error.Failed;
            //if (openssl.EVP_PKEY_fromdata(ctx, &pkey, openssl.EVP_PKEY_PUBLIC_KEY, &params[0]) <= 0)
            //	return error.Failed;
        },
        .ECDSA => |ecdsa| {
            var bn_x = openssl.BN_bin2bn(&ecdsa.X[0], @intCast(c_int, ecdsa.X.len), null) orelse return error.Failed;
            defer openssl.BN_free(bn_x);
            var bn_y = openssl.BN_bin2bn(&ecdsa.Y[0], @intCast(c_int, ecdsa.Y.len), null) orelse return error.Failed;
            defer openssl.BN_free(bn_y);

            var nid = switch (ecdsa.Curve) {
                .P256 => openssl.NID_X9_62_prime256v1,
                .P384 => openssl.NID_secp384r1,
                .P521 => openssl.NID_secp521r1,
            };

            var ec_key = openssl.EC_KEY_new_by_curve_name(nid) orelse return error.Failed;
            var group = openssl.EC_GROUP_new_by_curve_name(nid) orelse return error.Failed;
            var point = openssl.EC_POINT_new(group) orelse return error.Failed;

            if (openssl.EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, null) <= 0)
                return error.Failed;

            if (openssl.EC_KEY_set_public_key(ec_key, point) <= 0)
                return error.Failed;

            var pkey = openssl.EVP_PKEY_new() orelse return error.Failed;
            defer openssl.EVP_PKEY_free(pkey);

            if (openssl.EVP_PKEY_set1_EC_KEY(pkey, ec_key) <= 0)
                return error.Failed;

            try testVerifySignature(Key{ .type = .{ .ECDSA = ecdsa.Curve }, .pkey = pkey }, data, sig);
        },
    }
}

fn testVerifySignature(key: Key, data: []const u8, signature: []const u8) !void {
    var buf: [1024]u8 = undefined;
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

    var md_ctx = openssl.EVP_MD_CTX_create() orelse return error.SignatureVerifyFailed;
    defer openssl.EVP_MD_CTX_free(md_ctx);

    var hash = switch (key.type) {
        .RSA => openssl.EVP_sha256(),
        .ECDSA => |curve| switch (curve) {
            .P256 => openssl.EVP_sha256(),
            .P384 => openssl.EVP_sha384(),
            .P521 => openssl.EVP_sha512(),
        },
    };

    if (openssl.EVP_DigestVerifyInit(md_ctx, null, hash, null, key.pkey) <= 0)
        return error.SignatureVerifyFailed;
    if (openssl.EVP_DigestVerifyUpdate(md_ctx, &data[0], data.len) <= 0)
        return error.SignatureVerifyFailed;
    if (openssl.EVP_DigestVerifyFinal(md_ctx, &sig[0], sig.len) <= 0)
        return error.SignatureVerifyFailed;
}
