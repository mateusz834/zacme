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
    kid: ?[]const u8 = null,

    pub const Directory = struct {
        keyChange: [:0]const u8,
        newAccount: [:0]const u8,
        // TODO: how json parser handles this kind of slices?
        newNonce: [:0]const u8,
        newOrder: [:0]const u8,
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
        if (self.kid) |kid| self.allocator.free(kid);
    }

    const AcmeError = error{
        BadNonce,
    };

    fn handleACMEErrors(self: *Client, comptime notReportErr: ?AcmeError, response: *http.Respose) !void {
        // RFC 8555 6.7:
        // ACME servers can return
        // responses with an HTTP error response code (4XX or 5XX).
        // When the server responds with an error status, it SHOULD provide
        // additional information using a problem document [RFC7807].
        if (!(response.status >= 400 and response.status <= 599 and response.contentType == .JSONProblem)) return;

        const Result = struct {
            type: []const u8,
            detail: ?[]const u8 = null,
            algorithms: ?[][]const u8 = null,
            subproblems: ?[]Subproblem = null,

            pub const Subproblem = struct {
                type: []const u8,
                detail: ?[]const u8 = null,
                identifier: ?Identifier = null,

                pub const Identifier = struct {
                    type: []const u8,
                    value: []const u8,
                };
            };

            pub fn printSubproblems(s: *@This()) void {
                if (s.subproblems) |subproblems| for (subproblems) |subproblem| {
                    if (subproblem.detail == null) {
                        if (subproblem.identifier) |identifier| {
                            log.stderr.printf("subproblem: {s}, identifer: type: {s}, value: {s}", .{ subproblem.type, identifier.type, identifier.value });
                            return;
                        }
                        log.stderr.printf("subproblem: {s}", .{subproblem.type});
                    } else {
                        if (subproblem.identifier) |identifier| {
                            log.stderr.printf("subproblem: {s}: {s}, identifer: type: {s}, value: {s}", .{ subproblem.type, subproblem.detail.?, identifier.type, identifier.value });
                            return;
                        }
                        log.stderr.printf("subproblem: {s}: {s}", .{ subproblem.type, subproblem.detail.? });
                    }
                };
            }
        };

        const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
        var tokens = std.json.TokenStream.init(response.body);
        var resErr = try std.json.parse(Result, &tokens, parseOptions);
        defer std.json.parseFree(Result, resErr, parseOptions);

        const AcmeURNPrefix = "urn:ietf:params:acme:error:";

        // RFC 8555 6.5:
        // When a server rejects a request because its nonce value was
        // unacceptable (or not present), it MUST provide HTTP status code 400
        // (Bad Request), and indicate the ACME error type
        // "urn:ietf:params:acme:error:badNonce"
        if (response.status == 400) {
            if (notReportErr) |e| {
                if (std.mem.startsWith(u8, resErr.type, AcmeURNPrefix)) {
                    const err = resErr.type[AcmeURNPrefix.len..];
                    if (e == AcmeError.BadNonce and std.mem.eql(u8, err, "badNonce")) {
                        return AcmeError.BadNonce;
                    }
                }
            }
        }

        // RFC 8555 6.2:
        // If the client sends a JWS signed with an algorithm that the server
        // does not support, then the server MUST return an error with status
        // code 400 (Bad Request) and type
        // "urn:ietf:params:acme:error:badSignatureAlgorithm".  The problem
        // document returned with the error MUST include an "algorithms" field
        // with an array of supported "alg" values.
        if (response.status == 400) {
            if (std.mem.startsWith(u8, resErr.type, AcmeURNPrefix)) {
                const err = resErr.type[AcmeURNPrefix.len..];
                if (std.mem.eql(u8, err, "badSignatureAlgorithm")) {
                    if (resErr.detail == null) {
                        log.stderr.printf("acme error: {s}, supported signature algorithms: {?s}", .{ resErr.type, resErr.algorithms });
                    } else {
                        log.stderr.printf("acme error: {s}: {s}, supported signature algorithms: {?s}", .{ resErr.type, resErr.detail.?, resErr.algorithms });
                    }

                    resErr.printSubproblems();
                    return error.UnknownAcmeError;
                }
            }
        }

        if (resErr.detail == null) {
            log.stderr.printf("acme error: {s}", .{resErr.type});
        } else {
            log.stderr.printf("acme error: {s}: {s}", .{ resErr.type, resErr.detail.? });
        }

        resErr.printSubproblems();
        return error.UnknownAcmeError;
    }

    fn postQuery(self: *Client, url: [:0]const u8, comptime withJwk: bool, payload: anytype) !http.Respose {
        while (true) {
            var body = if (withJwk) blk: {
                const nonce = try self.getNonce();
                defer self.allocator.free(nonce);

                var body = try jws.withJWK(self.allocator, self.accountKey, payload, nonce, url);
                break :blk body;
            } else blk: {
                const kid = try self.getKID();

                const nonce = try self.getNonce();
                defer self.allocator.free(nonce);

                var body = try jws.withKID(self.allocator, self.accountKey, payload, nonce, url, kid);
                break :blk body;
            };
            defer self.allocator.free(body);

            // TODO: handle RFC 8555 6.6.  Rate Limits
            var out = try http.query(self.allocator, .{ .url = url, .method = .POST, .body = .{
                .content = body,
                .type = .JSON,
            } });
            errdefer out.deinit(self.allocator);

            // RFC 8555 6.3:
            // The server MUST include
            // a Replay-Nonce header field in every successful response to a POST
            // request and SHOULD provide it in error responses as well.
            try self.storeNonce(&out);

            self.handleACMEErrors(AcmeError.BadNonce, &out) catch |err| switch (err) {
                AcmeError.BadNonce => {
                    // RFC 8555 6.5: An error response with the
                    // "badNonce" error type MUST include a Replay-Nonce header field with a
                    // fresh nonce that the server will accept in a retry of the original
                    // query (and possibly in other requests, according to the server's
                    // nonce scoping policy).  On receiving such a response, a client SHOULD
                    // retry the request using the new nonce.

                    // The new nonce was stored by storeNonce (above), so retry the query.
                    out.deinit(self.allocator);
                    continue;
                },
                else => return err,
            };

            return out;
        }
    }

    fn storeNonce(self: *Client, response: *http.Respose) !void {
        if (self.nonce == null) {
            var nonces = response.headers.get("replay-nonce");
            if (nonces == null or nonces.?.len != 1) {
                return;
            }

            // TODO:
            // RFC 8555 6.5.1:
            // The value of the Replay-Nonce header field MUST be an octet string
            // encoded according to the base64url
            // Clients MUST ignore invalid Replay-Nonce values.
            // TODO: but also ignore them in the newNonce endpoint??

            // TODO: validate characters in this nonce.
            var nonce = try self.allocator.alloc(u8, nonces.?[0].len);
            std.mem.copy(u8, nonce, nonces.?[0]);
            self.nonce = nonce;
        }
    }

    fn queryWithJWK(self: *Client, url: [:0]const u8, payload: anytype) !http.Respose {
        return self.postQuery(url, true, payload);
    }

    fn queryWithKID(self: *Client, url: [:0]const u8, payload: anytype) !http.Respose {
        return self.postQuery(url, false, payload);
    }

    pub fn retreiveAccount(self: *Client) !void {
        const request = struct {
            onlyReturnExisting: bool = false,
        };

        const r = request{ .onlyReturnExisting = true };

        var directory = try self.getDirectory();

        log.stdout.printf("fetching ACME account from \"{s}\"", .{directory.newAccount});

        var out = try self.queryWithJWK(directory.newAccount, r);
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            try self.printErrorDetails(out.body);
            return error.AccountCreationFailure;
        }

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

        log.stdout.printf("fetching ACME account from \"{s}\"", .{directory.newAccount});

        var out = try self.queryWithJWK(directory.newAccount, r);
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            return error.AccountCreationFailure;
        }

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

        var out = try self.queryWithJWK(directory.newAccount, r);
        defer out.deinit(self.allocator);

        if (out.status != 201 and out.status != 200) {
            log.stdout.printf("failed while creating account, failed with status code: {}", .{out.status});
            return error.AccountCreationFailure;
        }

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

        const kid = try self.getKID();
        var out = try self.queryWithKID(kid, r);
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while deactivating the ACME account, failed with status code: {}", .{out.status});
            return error.AccountCreationFailure;
        }
    }

    pub fn rolloverAccountKey(self: *Client, newKey: crypto.Key) !void {
        const keyChange = struct {
            account: []const u8,
            oldKey: jws.JWK,
        };

        const kid = try self.getKID();

        var public = try self.accountKey.getPublicKey(self.allocator);
        defer public.deinit(self.allocator);

        var kc = keyChange{
            .account = kid,
            .oldKey = jws.JWK{ .public_key = &public, .allocator = self.allocator },
        };

        var dir = try self.getDirectory();

        var inner = try jws.withJWK(self.allocator, newKey, kc, null, dir.keyChange);
        defer self.allocator.free(inner);

        var out = try self.queryWithKID(dir.keyChange, inner);
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while making ACME key rollover, failed with status code: {}", .{out.status});
            return error.AccountKeyRolloverFailure;
        }

        //self.accountKey.deinit();
        self.accountKey = newKey;
    }

    pub const AccountUpdateRequest = struct {
        contact: ?[][]const u8,
    };

    pub fn updateAccount(self: *Client, r: AccountUpdateRequest) !void {
        const kid = try self.getKID();
        var out = try self.queryWithKID(kid, r);
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while updating the ACME account details, failed with status code: {}", .{out.status});
            return error.AccountUpdateFailure;
        }
    }

    fn getKID(self: *Client) ![:0]const u8 {
        if (self.kid) |kid| return kid[0 .. kid.len - 1 :0];

        var d = try self.retreiveAccountWithDetails(self.allocator);
        defer d.deinit(self.allocator);

        const kidZero = try self.allocator.alloc(u8, d.kid.len + 1);
        errdefer self.allocator.free(kidZero);

        std.mem.copy(u8, kidZero, d.kid);
        kidZero[d.kid.len] = 0;
        self.kid = kidZero;

        return kidZero[0..d.kid.len :0];
    }

    pub const CertificateIssuanceRequest = struct {
        identifiers: []Identifier,
        notBefore: ?i64 = null,
        notAfter: ?i64 = null,

        pub const Identifier = struct {
            type: Type,
            value: []const u8,

            pub const Type = enum {
                dns,

                fn string(self: Type) []const u8 {
                    return switch (self) {
                        .dns => "dns",
                    };
                }

                pub fn jsonStringify(
                    s: @This(),
                    options: std.json.StringifyOptions,
                    out_stream: anytype,
                ) @TypeOf(out_stream).Error!void {
                    return std.json.stringify(s.string(), options, out_stream);
                }
            };
        };
    };

    pub fn issueCertificate(self: *Client, request: CertificateIssuanceRequest) !void {
        var dir = try self.getDirectory();

        var out = try self.queryWithKID(dir.newOrder, request);
        defer out.deinit(self.allocator);

        if (out.status != 201) {
            log.stdout.printf("failed while requesting issuance of a certifiacte, failed with status code: {}", .{out.status});
            return error.CertIssuanceFailed;
        }

        const Response = struct {
            status: Status,
            authorizations: [][:0]const u8,
            finalize: []const u8,

            pub const Status = enum { invalid, pending, ready, processsing, valid };
        };

        var tokens = std.json.TokenStream.init(out.body);
        const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
        var res = try std.json.parse(Response, &tokens, parseOptions);
        defer std.json.parseFree(Response, res, parseOptions);
        log.stdout.printf("res: {}", .{res});

        for (res.authorizations) |authorization| {
            var a = try self.getAuthorization(authorization);
            defer a.deinit(self.allocator);
            log.stdout.printf("auth: {}", .{a});

            try self.startChallengeValidation(a.challenges[0].url);
            std.time.sleep(std.time.ns_per_s);
            try self.startChallengeValidation2(a.challenges[0].url);
        }
    }

    const Authorization = struct {
        status: Status,
        identifier: CertificateIssuanceRequest.Identifier,
        challenges: []Challenge,
        wildcard: bool = false,

        pub const Challenge = struct {
            type: []const u8,
            url: [:0]const u8,
            status: Challenge.Status,
            token: []const u8,

            pub const Status = enum { pending, processsing, valid, invalid };
        };

        pub const Status = enum { pending, valid, invalid, deactivated, exipred, revoked };

        pub fn deinit(self: Authorization, allocator: std.mem.Allocator) void {
            const parseOptions = .{ .allocator = allocator, .ignore_unknown_fields = true };
            std.json.parseFree(Authorization, self, parseOptions);
        }
    };

    fn getAuthorization(self: *Client, authURL: [:0]const u8) !Authorization {
        var out = try self.queryWithKID(authURL, @as([]const u8, ""));
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while retreiving Authorization, failed with status code: {}", .{out.status});
            return error.AuthorizaionRetrivalFailed;
        }

        var tokens = std.json.TokenStream.init(out.body);
        const parseOptions = .{ .allocator = self.allocator, .ignore_unknown_fields = true };
        var res = try std.json.parse(Authorization, &tokens, parseOptions);
        return res;
    }

    fn startChallengeValidation(self: *Client, challengeURL: [:0]const u8) !void {
        var out = try self.queryWithKID(challengeURL, @as([]const u8, "{}"));
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while requesting server to validate challange, failed with status code: {}", .{out.status});
            return error.StartChallengeValidationFailed;
        }
    }

    fn startChallengeValidation2(self: *Client, challengeURL: [:0]const u8) !void {
        var out = try self.queryWithKID(challengeURL, @as([]const u8, ""));
        defer out.deinit(self.allocator);

        if (out.status != 200) {
            log.stdout.printf("failed while requesting server to validate challange, failed with status code: {}", .{out.status});
            return error.StartChallengeValidationFailed;
        }
    }

    fn OutOfMemoryWriter(comptime W: type) type {
        return struct {
            writer_stream: W,
            pub fn writer(self: @This()) std.io.Writer(@This(), W.Error || std.mem.Allocator.Error, write) {
                return .{ .context = self };
            }

            fn write(context: @This(), bytes: []const u8) (W.Error || std.mem.Allocator.Error)!usize {
                return context.writer_stream.write(bytes);
            }
        };
    }

    // keyAuthToWriter writes the RFC 8555 8.1 Key Authorizations to the writer.
    fn keyAuthToWriter(self: *Client, token: []const u8, writer: anytype) !void {
        var public = try self.accountKey.getPublicKey(self.allocator);
        defer public.deinit(self.allocator);

        var sha256 = try crypto.StreamingSha256.init();
        defer sha256.deinit();

        const wrt = sha256.writer();

        // So that std.json.stringify() can return OutOfMemory with StreamingSha256
        var oom_writer = OutOfMemoryWriter(@TypeOf(wrt)){ .writer_stream = wrt };

        try std.json.stringify(jws.JWK{ .public_key = &public, .allocator = self.allocator }, .{}, oom_writer.writer());

        const thumbprint = try sha256.final();

        const base64ThumbprintLen = comptime std.base64.url_safe_no_pad.Encoder.calcSize(crypto.StreamingSha256.digestLength);
        var base64Thumbprint: [base64ThumbprintLen]u8 = undefined;

        try writer.writeAll(token);
        try writer.writeByte('.');
        try writer.writeAll(std.base64.url_safe_no_pad.Encoder.encode(&base64Thumbprint, &thumbprint));
    }

    fn keyAuth(self: *Client, token: []const u8) ![]const u8 {
        const base64ThumbprintLen = comptime std.base64.url_safe_no_pad.Encoder.calcSize(crypto.StreamingSha256.digestLength);
        var keyauth = try std.ArrayList(u8).initCapacity(self.allocator, token.len + 1 + base64ThumbprintLen);
        errdefer keyauth.deinit();
        try self.keyAuthToWriter(token, keyauth.writer());
        return keyauth.toOwnedSlice();
    }

    const DNS01ResourceRecordLength = std.base64.url_safe_no_pad.Encoder.calcSize(crypto.StreamingSha256.digestLength);
    fn DNS01ChallengeRecord(self: *Client, token: []const u8) ![DNS01ResourceRecordLength]u8 {
        var sha256 = try crypto.StreamingSha256.init();
        defer sha256.deinit();
        try self.keyAuthToWriter(token, sha256.writer());
        const digest = try sha256.final();

        var outBase64: [DNS01ResourceRecordLength]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&outBase64, &digest);
        return outBase64;
    }

    fn HTTP01ChallengeResponse(self: *Client, token: []const u8) ![]const u8 {
        return self.keyAuth(token);
    }

    fn getNonce(self: *Client) ![]const u8 {
        if (self.nonce != null) {
            defer self.nonce = null;
            return self.nonce.?;
        }

        // TODO: So maybe we shouldn't use the newNonce endpoint and use the badNonce
        // for receiving them??
        // Other than the constraint above with regard to nonces issued in
        // "badNonce" responses, ACME does not constrain how servers scope
        // nonces.  Clients MAY assume that nonces have broad scope, e.g., by
        // having a single pool of nonces used for all requests.  However, when
        // retrying in response to a "badNonce" error, the client MUST use the
        // nonce provided in the error response.  Servers should scope nonces
        // broadly enough that retries are not needed very often.

        // TODO: what is the use-case for POST-as-GET to thease resources?
        // TODO: should getNonce use POST-as-GET for newNonce requests after retreiveAccount??
        // TODO: POST-as-GET gives us Request URL Integrity (6.4) for newNonce. (is this useful?)
        // RFC 8555 6.3:
        // The server MUST allow GET requests for the directory and newNonce
        // resources (see Section 7.1), in addition to POST-as-GET requests for
        // these resources.  This enables clients to bootstrap into the ACME
        // authentication system.

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
