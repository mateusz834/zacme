const std = @import("std");
const http = @import("./http.zig");
const crypto = @import("./crypto.zig");
const jws = @import("./jws.zig");
const log = @import("./log.zig");

pub const Client = struct {
    allocator: std.mem.Allocator,
    directoryURL: [:0]const u8,
    accountKey: crypto.Key,

    directory: ?Directory = null,
    nonce: ?[]const u8 = null,

    pub const Directory = struct {
        keyChange: [:0]const u8,
        newAccount: [:0]const u8,
        // TODO: how json parser handles this kind of slices?
        newNonce: [:0]const u8,
        newOrder: []const u8,
        revokeCert: []const u8,
        meta: Meta,

        pub const Meta = struct {
            termsOfService: []const u8,
        };
    };

    pub fn init(allocator: std.mem.Allocator, directoryURL: [:0]const u8, accountKey: crypto.Key) Client {
        return .{
            .allocator = allocator,
            .directoryURL = directoryURL,
            .accountKey = accountKey,
        };
    }

    pub fn deinit(self: Client) void {
        if (self.nonce != null) self.allocator.free(self.nonce.?);
        if (self.directory != null) {
            const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
            std.json.parseFree(Directory, self.directory.?, parseOptions);
        }
    }

    fn printErrorDetails(self: *Client, body: []const u8) !void {
        const Result = struct {
            type: []const u8,
            detail: ?[]const u8,
        };

        const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
        var tokens = std.json.TokenStream.init(body);
        var resErr = try std.json.parse(Result, &tokens, parseOptions);
        defer std.json.parseFree(Result, resErr, parseOptions);

        if (resErr.detail == null) {
            log.stderr.printf("caused by: {s}", .{resErr.type});
        } else {
            log.stderr.printf("caused by: {s}: {s}", .{ resErr.type, resErr.detail.? });
        }
    }

    pub fn retreiveAccount(self: *Client) !void {
        const request = struct {
            onlyReturnExisting: bool = false,
        };

        const r = request{ .onlyReturnExisting = true };

        var directory = try self.getDirectory();

        const nonce = try self.getNonce();
        defer self.allocator.free(nonce);

        log.stdout.printf("fetching ACME account from \"{s}\"", .{directory.newAccount});

        var body = try jws.withJWK(self.allocator, self.accountKey, r, nonce, directory.newAccount);
        defer self.allocator.free(body);

        var out = try http.query(self.allocator, .{ .url = directory.newAccount, .method = .POST, .body = .{
            .content = body,
            .type = .JSON,
        } });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            try self.printErrorDetails(out.body);
            return error.AccountCreationFailure;
        }

        try self.storeNonce(&out);

        const locations = out.headers.get("location");
        if (locations == null or locations.?.len != 1) {
            log.stdout.printf("ACME server did not respond with Location header", .{});
            return error.NewNonceFailure;
        }

        const kid = locations.?[0];
        log.stdout.printf("Found ACME account with KID \"{s}\"", .{kid});
    }

    pub const AccountDetails = struct {
        kid: []const u8,
        status: Status,
        contact: ?[][]const u8,

        pub const Status = enum {
            Valid,
            Deactivated,
            Revoked,
            pub fn string(self: Status) []const u8 {
                return switch (self) {
                    .Valid => "valid",
                    .Deactivated => "deactivated",
                    .Revoked => "revoked",
                };
            }
        };

        pub fn deinit(self: *AccountDetails, allocator: std.mem.Allocator) void {
            allocator.free(self.kid);
            if (self.contact) |contact| {
                for (contact) |v| {
                    allocator.free(v);
                }
                allocator.free(contact);
            }
        }
    };

    pub fn retreiveAccountWithDetails(self: *Client, detailsAllocator: std.mem.Allocator) !AccountDetails {
        const request = struct {
            onlyReturnExisting: bool = false,
        };

        const r = request{ .onlyReturnExisting = true };

        var directory = try self.getDirectory();

        const nonce = try self.getNonce();
        defer self.allocator.free(nonce);

        log.stdout.printf("fetching ACME account from \"{s}\"", .{directory.newAccount});

        var body = try jws.withJWK(self.allocator, self.accountKey, r, nonce, directory.newAccount);
        defer self.allocator.free(body);

        var out = try http.query(self.allocator, .{ .url = directory.newAccount, .method = .POST, .body = .{
            .content = body,
            .type = .JSON,
        } });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            try self.printErrorDetails(out.body);
            return error.AccountCreationFailure;
        }

        try self.storeNonce(&out);

        const locations = out.headers.get("location");
        if (locations == null or locations.?.len != 1) {
            log.stdout.printf("ACME server did not respond with Location header", .{});
            return error.NewNonceFailure;
        }

        const kid = try detailsAllocator.alloc(u8, locations.?[0].len);
        errdefer detailsAllocator.free(kid);
        std.mem.copy(u8, kid, locations.?[0]);

        log.stdout.printf("Found ACME account with KID \"{s}\"", .{kid});

        const Respose = struct {
            status: []const u8,
            contact: ?[][]const u8 = null,
        };
        var tokens = std.json.TokenStream.init(out.body);
        const parseOptions = .{ .allocator = detailsAllocator, .ignore_unknown_fields = true };
        var res = try std.json.parse(Respose, &tokens, parseOptions);

        defer std.json.parseFree(Respose, res, parseOptions);

        // so that json.parseFree does not free it.
        defer res.contact = null;

        var status: AccountDetails.Status = if (std.mem.eql(u8, res.status, "valid"))
            .Valid
        else if (std.mem.eql(u8, res.status, "deactivated"))
            .Deactivated
        else if (std.mem.eql(u8, res.status, "revoked"))
            .Revoked
        else
            return error.UnknownStatus;

        return .{
            .kid = kid,
            .contact = res.contact,
            .status = status,
        };
    }

    pub fn createAccount(self: *Client, contact: ?[][]const u8, comptime acceptTOS: fn ([]const u8) bool) !void {
        const request = struct {
            contact: ?[][]const u8,
            termsOfServiceAgreed: bool,
        };

        var directory = try self.getDirectory();
        log.stdout.printf("creating ACME account on \"{s}\"", .{directory.newAccount});

        const r = request{
            .contact = contact,
            .termsOfServiceAgreed = acceptTOS(directory.meta.termsOfService),
        };

        const nonce = try self.getNonce();
        defer self.allocator.free(nonce);

        var body = try jws.withJWK(self.allocator, self.accountKey, r, nonce, directory.newAccount);
        defer self.allocator.free(body);

        var out = try http.query(self.allocator, .{ .url = directory.newAccount, .method = .POST, .body = .{
            .content = body,
            .type = .JSON,
        } });
        defer out.deinit(self.allocator);

        if (out.status != 201 and out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            return error.AccountCreationFailure;
        }

        try self.storeNonce(&out);

        const locations = out.headers.get("location");
        if (locations == null or locations.?.len != 1) {
            log.stdout.printf("ACME server did not respond with Location header", .{});
            return error.NewNonceFailure;
        }

        const kid = locations.?[0];
        if (out.status == 200) {
            log.stdout.printf("failed while creating account, key is binded with account KID: \"{s}\"", .{kid});
            return error.AccountCreationFailure;
        }

        log.stdout.printf("succesfully created account with KID: \"{s}\"", .{kid});
    }

    pub fn deactivateAccount(self: *Client) !void {
        const request = struct {
            status: []const u8,
        };

        const r = request{ .status = "deactivated" };

        var d = try self.retreiveAccountWithDetails(self.allocator);
        defer d.deinit(self.allocator);

        const nonce = try self.getNonce();
        defer self.allocator.free(nonce);

        // TODO: eliminate that step
        // store null-terminaked kid in Client.
        const kidZero = try self.allocator.alloc(u8, d.kid.len + 1);
        defer self.allocator.free(kidZero);
        std.mem.copy(u8, kidZero, d.kid);
        kidZero[d.kid.len] = 0;

        var body = try jws.withKID(self.allocator, self.accountKey, r, nonce, d.kid, d.kid);
        defer self.allocator.free(body);

        var out = try http.query(self.allocator, .{ .url = kidZero[0..d.kid.len :0], .method = .POST, .body = .{
            .content = body,
            .type = .JSON,
        } });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while deactivating the ACME account, failed with status code: {}", .{out.status});
            return error.AccountCreationFailure;
        }

        try self.storeNonce(&out);
    }

    pub fn rolloverAccountKey(self: *Client, newKey: crypto.Key) !void {
        const keyChange = struct {
            account: []const u8,
            oldKey: jws.JWK,
        };

        var d = try self.retreiveAccountWithDetails(self.allocator);
        defer d.deinit(self.allocator);

        var public = try self.accountKey.getPublicKey(self.allocator);
        defer public.deinit(self.allocator);

        var kc = keyChange{
            .account = d.kid,
            .oldKey = try jws.JWK.fromCryptoPublicKey(self.allocator, public),
        };
        defer kc.oldKey.deinit(self.allocator);

        var dir = try self.getDirectory();

        var inner = try jws.withJWK(self.allocator, newKey, kc, null, dir.keyChange);
        defer self.allocator.free(inner);

        const nonce = try self.getNonce();
        defer self.allocator.free(nonce);

        var body = try jws.withKID(self.allocator, self.accountKey, inner, nonce, dir.keyChange, d.kid);
        defer self.allocator.free(body);

        var out = try http.query(self.allocator, .{ .url = dir.keyChange, .method = .POST, .body = .{
            .content = body,
            .type = .JSON,
        } });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while making ACME key rollover, failed with status code: {}", .{out.status});
            return error.AccountKeyRolloverFailure;
        }

        try self.storeNonce(&out);

        //self.accountKey.deinit();
        self.accountKey = newKey;
    }

    fn storeNonce(self: *Client, response: *http.Respose) !void {
        if (self.nonce == null) {
            var nonces = response.headers.get("replay-nonce");
            if (nonces == null or nonces.?.len != 1) {
                return;
            }
            // TODO: validate characters in this nonce.
            var nonce = try self.allocator.alloc(u8, nonces.?[0].len);
            std.mem.copy(u8, nonce, nonces.?[0]);
            self.nonce = nonce;
        }
    }

    fn getNonce(self: *Client) ![]const u8 {
        if (self.nonce != null) {
            defer self.nonce = null;
            return self.nonce.?;
        }

        var directory = try self.getDirectory();
        log.stdout.printf("fetching ACME nonce from: \"{s}\"", .{directory.newNonce});

        var out = try http.query(self.allocator, .{
            .url = directory.newNonce,
            .method = .HEAD,
        });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("fetching ACME nonce failed with HTTP status code: {}", .{out.status});
            return error.NewNonceFailure;
        }

        var nonces = out.headers.get("replay-nonce");
        if (nonces == null or nonces.?.len != 1) {
            log.stdout.printf("ACME server did not respond with Replay-Nonce header", .{});
            return error.NewNonceFailure;
        }

        // TODO: validate characters in this nonce.
        var nonce = try self.allocator.alloc(u8, nonces.?[0].len);
        std.mem.copy(u8, nonce, nonces.?[0]);
        return nonce;
    }

    fn getDirectory(self: *Client) !Directory {
        if (self.directory != null) {
            return self.directory.?;
        }

        log.stdout.printf("fetching ACME directory from: \"{s}\"", .{self.directoryURL});

        var out = try http.query(self.allocator, .{
            .url = self.directoryURL,
            .method = .GET,
        });
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("fetching ACME directory failed with HTTP status code: {}", .{out.status});
            return error.ClientConfigurationFailed;
        }

        var tokens = std.json.TokenStream.init(out.body);
        const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
        self.directory = try std.json.parse(Directory, &tokens, parseOptions);
        return self.directory.?;
    }
};
