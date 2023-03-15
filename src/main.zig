const std = @import("std");
const log = @import("./log.zig");
const http = @import("./http.zig");
const crypto = @import("./crypto.zig");
const jws = @import("./jws.zig");
const acme = @import("./acme.zig");
const cmd = @import("./cmd.zig");

pub fn json_pretty(allocator: std.mem.Allocator, inJson: []const u8) ![]const u8 {
    var parser = std.json.Parser.init(allocator, true);
    defer parser.deinit();

    var valTree = try parser.parse(inJson);
    defer valTree.deinit();

    var json = try std.json.stringifyAlloc(allocator, valTree.root, .{ .whitespace = .{ .indent = .{ .Space = 2 } } });
    return json;
}

const curl = @cImport({
    @cInclude("curl/curl.h");
});

const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl.h");
});

const lencr = "https://acme-staging-v02.api.letsencrypt.org/directory";

pub fn main() !u8 {
    defer http.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var kk = blk: {
        var keyPEM = try std.fs.cwd().readFileAlloc(allocator, "key.pem", std.math.maxInt(usize));
        defer allocator.free(keyPEM);
        break :blk try crypto.Key.from_pem(allocator, keyPEM);
    };
    defer kk.deinit();

    var cc = acme.Client.init(allocator, lencr, kk);
    defer cc.deinit();

    var idents = [_]acme.Client.CertificateIssuanceRequest.Identifier{
        .{ .type = .dns, .value = "d-nks.eu.org" },
    };

    try cc.issueCertificate(.{
        .identifiers = &idents,
    });

    var c = cmd.Cmd.parseFromArgs(allocator) catch return 1;
    defer c.deinit();

    switch (c.command) {
        .CreateAccountFromKeyFile => |create| {
            var key = if (create.generateKey == null) blk: {
                var keyPEM = try std.fs.cwd().readFileAlloc(allocator, create.file, std.math.maxInt(usize));
                defer allocator.free(keyPEM);
                break :blk try crypto.Key.from_pem(allocator, keyPEM);
            } else blk: {
                var key = try crypto.Key.generate(create.generateKey.?);
                errdefer key.deinit();

                var keyPEM = try key.to_pem(allocator);
                defer allocator.free(keyPEM);

                var file = try std.fs.cwd().createFile(create.file, .{
                    .exclusive = true,
                    .mode = 0o660,
                });
                defer file.close();
                try file.writeAll(keyPEM);
                break :blk key;
            };
            defer key.deinit();

            var client = acme.Client.init(allocator, if (create.acmeURL) |v| v else lencr, key);
            defer client.deinit();

            if (create.forceTosAccept) {
                const Closure = struct {
                    pub fn acceptTos(_: []const u8) bool {
                        return true;
                    }
                };
                try client.createAccount(create.contact, Closure.acceptTos);
            } else {
                const Closure = struct {
                    pub fn acceptTos(tosURL: []const u8) bool {
                        std.io.getStdOut().writer().print("Do you accept the terms of service avaliable at: \"{s}\"?", .{tosURL}) catch {};
                        std.io.getStdOut().writer().print("\n[Y/N]: ", .{}) catch {};
                        var char: [1]u8 = undefined;
                        var num = std.io.getStdIn().read(&char) catch 0;
                        if (num == 0 or !(char[0] == 'Y' or char[0] == 'y')) {
                            return false;
                        }
                        return true;
                    }
                };
                try client.createAccount(create.contact, Closure.acceptTos);
            }
        },
        .AccountDetails => |details| {
            var keyPEM = try std.fs.cwd().readFileAlloc(allocator, details.file, std.math.maxInt(usize));
            defer allocator.free(keyPEM);
            var key = try crypto.Key.from_pem(allocator, keyPEM);

            var client = acme.Client.init(allocator, if (details.acmeURL) |v| v else lencr, key);
            defer client.deinit();

            var d = try client.retreiveAccountWithDetails(allocator);
            defer d.deinit(allocator);

            std.io.getStdOut().writer().print("KID: \"{s}\"\n", .{d.kid}) catch {};
            std.io.getStdOut().writer().print("Status: \"{s}\"\n", .{d.status.string()}) catch {};
            if (d.contact) |contacts| {
                for (contacts) |contact| {
                    std.io.getStdOut().writer().print("Contact: \"{s}\"\n", .{contact}) catch {};
                }
            }
        },
        .DeactivateAccount => |deactivate| {
            var keyPEM = try std.fs.cwd().readFileAlloc(allocator, deactivate.file, std.math.maxInt(usize));
            defer allocator.free(keyPEM);
            var key = try crypto.Key.from_pem(allocator, keyPEM);

            var client = acme.Client.init(allocator, if (deactivate.acmeURL) |v| v else lencr, key);
            defer client.deinit();

            try client.deactivateAccount();
        },
        .AccountKeyRollover => |rollover| {
            var key = blk: {
                var keyPEM = try std.fs.cwd().readFileAlloc(allocator, rollover.file, std.math.maxInt(usize));
                defer allocator.free(keyPEM);
                break :blk try crypto.Key.from_pem(allocator, keyPEM);
            };
            defer key.deinit();

            var newKey = if (rollover.generateKey == null) blk: {
                var keyPEM = try std.fs.cwd().readFileAlloc(allocator, rollover.newFile, std.math.maxInt(usize));
                defer allocator.free(keyPEM);
                break :blk try crypto.Key.from_pem(allocator, keyPEM);
            } else blk: {
                var newKey = try crypto.Key.generate(rollover.generateKey.?);
                errdefer newKey.deinit();

                var keyPEM = try newKey.to_pem(allocator);
                defer allocator.free(keyPEM);

                var file = try std.fs.cwd().createFile(rollover.newFile, .{
                    .exclusive = true,
                    .mode = 0o660,
                });
                defer file.close();
                try file.writeAll(keyPEM);
                break :blk newKey;
            };
            defer newKey.deinit();

            var client = acme.Client.init(allocator, if (rollover.acmeURL) |v| v else lencr, key);
            defer client.deinit();

            try client.rolloverAccountKey(newKey);
        },
        .AccountUpdate => |update| {
            var key = blk: {
                var keyPEM = try std.fs.cwd().readFileAlloc(allocator, update.file, std.math.maxInt(usize));
                defer allocator.free(keyPEM);
                break :blk try crypto.Key.from_pem(allocator, keyPEM);
            };
            defer key.deinit();

            var client = acme.Client.init(allocator, if (update.acmeURL) |v| v else lencr, key);
            defer client.deinit();

            try client.updateAccount(.{
                .contact = update.contact,
            });
        },
    }

    //var rsaPEM = try std.fs.cwd().readFileAlloc(allocator, "key.pem", 1 << 16);
    //defer allocator.free(rsaPEM);

    //var rsa = try crypto.Key.from_pem(allocator, rsaPEM);
    //defer rsa.deinit();

    //var client = acme.Client.init(allocator, "https://acme-staging-v02.api.letsencrypt.org/directory", rsa);
    //defer client.deinit();
    //try client.retreiveAccount();

    //log.stdout.print("generating RSA-2048");

    //var public = try rsa.getPublicKey(allocator);
    //defer public.deinit(allocator);
    //log.stderr.printf("{}", .{public});

    ////var sign = try rsa.sign(allocator, "siema");
    ////defer allocator.fre(sign);

    ////log.stdout.printf("signature: {x}", .{std.fmt.fmtSliceHexLower(sign)});

    //log.stdout.print("generating ECDSA P256");
    //var ecdsa = try crypto.Key.generate(.{ .ECDSA = .P256 });

    //var pem = try std.fs.cwd().readFileAlloc(allocator, "./file.pem", 11111111111);
    //defer allocator.free(pem);

    //var key = try crypto.Key.from_pem(allocator, pem);
    //log.stderr.printf("key type: {}", .{key.type});

    //var pem2 = try key.to_pem(allocator);
    //defer allocator.free(pem2);

    //log.stderr.printf("{s}", .{pem2});

    //var signt = try key.sign(allocator, "siema");
    //defer allocator.free(signt);

    //log.stderr.printf("{s}", .{std.fmt.fmtSliceHexLower(signt)});

    //var j = try jws.withKID(allocator, rsa, "b", "c", "bb", "oo");
    //defer allocator.free(j);

    //log.stderr.printf("{s}", .{j});

    //var j2 = try jws.withJWK(allocator, rsa, "b", "c", "bb");
    //defer allocator.free(j2);

    //log.stderr.printf("{s}", .{j2});

    //var j3 = try jws.withJWK(allocator, ecdsa, "b", "c", "bb");
    //defer allocator.free(j3);

    //log.stderr.printf("{s}", .{j3});

    //var md = openssl.EVP_MD_CTX_new() orelse {
    //    log.err("failed while creating EVP_MD_CTX");
    //    return error.EVPMDNEw;
    //};
    //var pctx: ?*openssl.EVP_PKEY_CTX = null;

    //var signOut = openssl.EVP_DigestSignInit(md, &pctx, openssl.EVP_sha256(), null, rsa);
    //if (signOut <= 0) {
    //    openssl.EVP_MD_CTX_free(md);
    //    return error.skfshi;
    //}

    //var padOut = openssl.EVP_PKEY_CTX_set_rsa_padding(pctx, openssl.RSA_PKCS1_PADDING);
    //if (padOut <= 0) {
    //    openssl.EVP_MD_CTX_free(md);
    //    return error.skfshi;
    //}

    //padOut = openssl.EVP_DigestUpdate(md, "siema", 5);
    //if (padOut <= 0) {
    //    openssl.EVP_MD_CTX_free(md);
    //    return error.skfshi;
    //}

    return 0;
}

pub fn sss(allocator: std.mem.Allocator) !u8 {
    const payload =
        \\{   "vals": {
        \\        "testing": 1,
        \\        "production": 42,
        \\        "sth": {
        \\				"sth": 3
        \\		  }
        \\    },
        \\    "uptime": 2999 }
    ;

    var str = try json_pretty(allocator, payload);
    defer allocator.free(str);

    log.stdout.printf("{s}", .{str});

    return 0;
}

fn writeToArrayListCallback(data: *anyopaque, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var buffer = @intToPtr(*std.ArrayList(u8), @ptrToInt(user_data));
    var typed_data = @intToPtr([*]u8, @ptrToInt(data));
    buffer.appendSlice(typed_data[0 .. nmemb * size]) catch return 0;
    return nmemb * size;
}

const cURL = @cImport({
    @cInclude("curl/curl.h");
});

pub fn sendRequest() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // curl easy handle init, or fail
    const handle = cURL.curl_easy_init() orelse return error.CURLHandleInitFailed;
    defer cURL.curl_easy_cleanup(handle);

    var response_buffer = std.ArrayList(u8).init(allocator);

    // superfluous when using an arena allocator, but
    // important if the allocator implementation changes
    defer response_buffer.deinit();

    // setup curl options
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_URL, "https://ziglang.org") != cURL.CURLE_OK)
        return error.CouldNotSetURL;

    // set write function callbacks
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_WRITEFUNCTION, writeToArrayListCallback) != cURL.CURLE_OK)
        return error.CouldNotSetWriteCallback;
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_WRITEDATA, &response_buffer) != cURL.CURLE_OK)
        return error.CouldNotSetWriteCallback;

    // perform
    if (cURL.curl_easy_perform(handle) != cURL.CURLE_OK)
        return error.FailedToPerformRequest;

    std.log.info("Got response of {d} bytes", .{response_buffer.items.len});
    std.debug.print("{s}\n", .{response_buffer.items});
}

test {
    _ = crypto;
}
