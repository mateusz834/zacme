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
    return 0;
}

test {
    _ = crypto;
}
