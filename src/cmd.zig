const std = @import("std");
const log = @import("./log.zig");
const crypto = @import("./crypto.zig");

pub const Cmd = struct {
    argIter: std.process.ArgIterator,
    allocator: std.mem.Allocator,

    command: Command,

    pub const Command = union(enum) {
        CreateAccountFromKeyFile: struct {
            file: []const u8,
            generateKey: ?crypto.Key.Type = null,
            forceTosAccept: bool,
            acmeURL: ?[:0]const u8,
            contact: ?[][]const u8 = null,
        },
        AccountDetails: struct {
            file: []const u8,
            acmeURL: ?[:0]const u8,
        },
        DeactivateAccount: struct {
            file: []const u8,
            acmeURL: ?[:0]const u8,
        },
        AccountKeyRollover: struct {
            file: []const u8,
            newFile: []const u8,
            generateKey: ?crypto.Key.Type = null,
            acmeURL: ?[:0]const u8,
        },
        AccountUpdate: struct {
            file: []const u8,
            contact: ?[][]const u8,
            acmeURL: ?[:0]const u8,
        },
    };

    fn printUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} [command]", .{programName});
        log.stdout.printf("Commands:", .{});
        log.stdout.printf(" - account - manage ACME account", .{});
    }

    fn printAccountUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account [command]", .{programName});
        log.stdout.printf("Commands:", .{});
        log.stdout.printf(" - create      create new ACME account", .{});
        log.stdout.printf(" - details     retreive ACME account details", .{});
        log.stdout.printf(" - deactivate  deactivate ACME account", .{});
        log.stdout.printf(" - rollover    rollover the ACME account key", .{});
        log.stdout.printf(" - update      update ACME account information", .{});
    }

    fn printAccountCreateUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account create [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --tosaccept        agree to terms of service without user interacton", .{});
        log.stdout.printf("  --contact contact  provide ACME contact information (multiple allowed)", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --genkey alg       generate a new key that will be stored in keyfile", .{});
        log.stdout.printf("                     alg is one of following: RSA-size (e.g. RSA-2048), P256, P384, P521", .{});
        log.stdout.printf("                     defaults to P384", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    fn printAccountDetailsUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account kid [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    fn printAccountDeactivateUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account deactivate [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    fn printAccountRolloverUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account rollover [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --newkeyfile path  PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --genkey alg       generate a new key that will be stored in keyfile", .{});
        log.stdout.printf("                     alg is one of following: RSA-size (e.g. RSA-2048), P256, P384, P521", .{});
        log.stdout.printf("                     defaults to P384", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    fn printAccountUpdateUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account update [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --contact contact  provide ACME contact information (multiple allowed)", .{});
        log.stdout.printf("  --removecontact    remove contact information", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    pub const ParseArgsError = error{
        InvalidArgs,
        WantHelp,
    } || std.mem.Allocator.Error;

    fn parseAccountCreate(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        var expectValueFor: ?enum { Contact, File, ACME, Key } = null;

        var keyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;
        var generateKey: ?crypto.Key.Type = null;
        var tosAccept = false;
        var contact = std.ArrayList([]const u8).init(allocator);
        errdefer contact.deinit();

        while (args.next()) |createArg| {
            if (expectValueFor) |valFor| {
                switch (valFor) {
                    .Contact => try contact.append(createArg),
                    .File => {
                        if (keyFile != null) return error.InvalidArgs;
                        keyFile = createArg;
                    },
                    .ACME => {
                        if (acmeURL != null) return error.InvalidArgs;
                        acmeURL = createArg;
                    },
                    .Key => {
                        if (generateKey != null) return error.InvalidArgs;

                        const rsaPrefix = "RSA-";
                        generateKey = if (std.mem.eql(u8, createArg, "P256"))
                            .{ .ECDSA = .P256 }
                        else if (std.mem.eql(u8, createArg, "P384"))
                            .{ .ECDSA = .P384 }
                        else if (std.mem.eql(u8, createArg, "P521"))
                            .{ .ECDSA = .P521 }
                        else if (std.mem.startsWith(u8, createArg, rsaPrefix))
                            .{ .RSA = std.fmt.parseInt(u32, createArg[rsaPrefix.len..], 10) catch return error.InvalidArgs }
                        else
                            return error.InvalidArgs;
                    },
                }

                expectValueFor = null;
                continue;
            }

            if (std.mem.eql(u8, createArg, "--tosaccept")) {
                if (tosAccept) return error.InvalidArgs else tosAccept = true;
            } else if (std.mem.eql(u8, createArg, "--contact")) {
                expectValueFor = .Contact;
            } else if (std.mem.eql(u8, createArg, "--keyfile")) {
                expectValueFor = .File;
            } else if (std.mem.eql(u8, createArg, "--acme")) {
                expectValueFor = .ACME;
            } else if (std.mem.eql(u8, createArg, "--genkey")) {
                expectValueFor = .Key;
            } else if (std.mem.eql(u8, createArg, "--help")) {
                return error.WantHelp;
            } else {
                return error.InvalidArgs;
            }
        }

        if (expectValueFor != null or keyFile == null) {
            return error.InvalidArgs;
        }

        return .{ .CreateAccountFromKeyFile = .{
            .file = keyFile.?,
            .forceTosAccept = tosAccept,
            .generateKey = generateKey,
            .contact = if (contact.items.len == 0) null else try contact.toOwnedSlice(),
            .acmeURL = acmeURL,
        } };
    }

    fn parseAccountDetails(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        _ = allocator;
        var expectValueFor: ?enum { File, ACME } = null;

        var keyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;

        while (args.next()) |createArg| {
            if (expectValueFor) |valFor| {
                switch (valFor) {
                    .File => {
                        if (keyFile != null) return error.InvalidArgs;
                        keyFile = createArg;
                    },
                    .ACME => {
                        if (acmeURL != null) return error.InvalidArgs;
                        acmeURL = createArg;
                    },
                }

                expectValueFor = null;
                continue;
            }

            if (std.mem.eql(u8, createArg, "--keyfile")) {
                expectValueFor = .File;
            } else if (std.mem.eql(u8, createArg, "--acme")) {
                expectValueFor = .ACME;
            } else if (std.mem.eql(u8, createArg, "--help")) {
                return error.WantHelp;
            } else {
                return error.InvalidArgs;
            }
        }

        if (expectValueFor != null or keyFile == null) {
            return error.InvalidArgs;
        }

        return .{ .AccountDetails = .{
            .file = keyFile.?,
            .acmeURL = acmeURL,
        } };
    }

    fn parseAccountDeactivate(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        _ = allocator;
        var expectValueFor: ?enum { File, ACME } = null;

        var keyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;

        while (args.next()) |createArg| {
            if (expectValueFor) |valFor| {
                switch (valFor) {
                    .File => {
                        if (keyFile != null) return error.InvalidArgs;
                        keyFile = createArg;
                    },
                    .ACME => {
                        if (acmeURL != null) return error.InvalidArgs;
                        acmeURL = createArg;
                    },
                }

                expectValueFor = null;
                continue;
            }

            if (std.mem.eql(u8, createArg, "--keyfile")) {
                expectValueFor = .File;
            } else if (std.mem.eql(u8, createArg, "--acme")) {
                expectValueFor = .ACME;
            } else if (std.mem.eql(u8, createArg, "--help")) {
                return error.WantHelp;
            } else {
                return error.InvalidArgs;
            }
        }

        if (expectValueFor != null or keyFile == null) {
            return error.InvalidArgs;
        }

        return .{ .DeactivateAccount = .{
            .file = keyFile.?,
            .acmeURL = acmeURL,
        } };
    }

    fn parseAccountRollover(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        _ = allocator;
        var expectValueFor: ?enum { File, NewFile, Key, ACME } = null;

        var keyFile: ?[]const u8 = null;
        var newKeyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;
        var generateKey: ?crypto.Key.Type = null;

        while (args.next()) |createArg| {
            if (expectValueFor) |valFor| {
                switch (valFor) {
                    .File => {
                        if (keyFile != null) return error.InvalidArgs;
                        keyFile = createArg;
                    },
                    .NewFile => {
                        if (newKeyFile != null) return error.InvalidArgs;
                        newKeyFile = createArg;
                    },
                    .ACME => {
                        if (acmeURL != null) return error.InvalidArgs;
                        acmeURL = createArg;
                    },
                    .Key => {
                        if (generateKey != null) return error.InvalidArgs;

                        const rsaPrefix = "RSA-";
                        generateKey = if (std.mem.eql(u8, createArg, "P256"))
                            .{ .ECDSA = .P256 }
                        else if (std.mem.eql(u8, createArg, "P384"))
                            .{ .ECDSA = .P384 }
                        else if (std.mem.eql(u8, createArg, "P521"))
                            .{ .ECDSA = .P521 }
                        else if (std.mem.startsWith(u8, createArg, rsaPrefix))
                            .{ .RSA = std.fmt.parseInt(u32, createArg[rsaPrefix.len..], 10) catch return error.InvalidArgs }
                        else
                            return error.InvalidArgs;
                    },
                }

                expectValueFor = null;
                continue;
            }

            if (std.mem.eql(u8, createArg, "--keyfile")) {
                expectValueFor = .File;
            } else if (std.mem.eql(u8, createArg, "--newkeyfile")) {
                expectValueFor = .NewFile;
            } else if (std.mem.eql(u8, createArg, "--acme")) {
                expectValueFor = .ACME;
            } else if (std.mem.eql(u8, createArg, "--genkey")) {
                expectValueFor = .Key;
            } else if (std.mem.eql(u8, createArg, "--help")) {
                return error.WantHelp;
            } else {
                return error.InvalidArgs;
            }
        }

        if (expectValueFor != null or keyFile == null or newKeyFile == null) {
            return error.InvalidArgs;
        }

        return .{ .AccountKeyRollover = .{
            .file = keyFile.?,
            .newFile = newKeyFile.?,
            .generateKey = generateKey,
            .acmeURL = acmeURL,
        } };
    }

    fn parseAccountUpdate(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        var expectValueFor: ?enum { File, ACME, Contact } = null;

        var keyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;

        var removeContact = false;
        var contact = std.ArrayList([]const u8).init(allocator);
        errdefer contact.deinit();

        while (args.next()) |createArg| {
            if (expectValueFor) |valFor| {
                switch (valFor) {
                    .Contact => try contact.append(createArg),
                    .File => {
                        if (keyFile != null) return error.InvalidArgs;
                        keyFile = createArg;
                    },
                    .ACME => {
                        if (acmeURL != null) return error.InvalidArgs;
                        acmeURL = createArg;
                    },
                }

                expectValueFor = null;
                continue;
            }

            if (std.mem.eql(u8, createArg, "--keyfile")) {
                expectValueFor = .File;
            } else if (std.mem.eql(u8, createArg, "--acme")) {
                expectValueFor = .ACME;
            } else if (std.mem.eql(u8, createArg, "--contact")) {
                expectValueFor = .Contact;
            } else if (std.mem.eql(u8, createArg, "--removecontact")) {
                removeContact = true;
            } else if (std.mem.eql(u8, createArg, "--help")) {
                return error.WantHelp;
            } else {
                return error.InvalidArgs;
            }
        }

        if (expectValueFor != null or keyFile == null or (removeContact and contact.items.len != 0) or (!removeContact and contact.items.len == 0)) {
            return error.InvalidArgs;
        }

        return .{ .AccountUpdate = .{
            .file = keyFile.?,
            .acmeURL = acmeURL,
            .contact = if (contact.items.len != 0 or removeContact) try contact.toOwnedSlice() else null,
        } };
    }

    pub fn parseFromArgs(allocator: std.mem.Allocator) !Cmd {
        var args = try std.process.argsWithAllocator(allocator);
        errdefer args.deinit();

        var programName: [:0]const u8 = if (args.next()) |arg| arg else unreachable;

        var command: Command = if (args.next()) |arg| blk: {
            if (std.mem.eql(u8, arg, "account")) {
                if (args.next()) |accountOp| {
                    if (std.mem.eql(u8, accountOp, "create")) {
                        break :blk Cmd.parseAccountCreate(allocator, &args) catch |err| {
                            Cmd.printAccountCreateUsage(programName);
                            return err;
                        };
                    } else if (std.mem.eql(u8, accountOp, "details")) {
                        break :blk Cmd.parseAccountDetails(allocator, &args) catch |err| {
                            Cmd.printAccountDetailsUsage(programName);
                            return err;
                        };
                    } else if (std.mem.eql(u8, accountOp, "deactivate")) {
                        break :blk Cmd.parseAccountDeactivate(allocator, &args) catch |err| {
                            Cmd.printAccountDeactivateUsage(programName);
                            return err;
                        };
                    } else if (std.mem.eql(u8, accountOp, "rollover")) {
                        break :blk Cmd.parseAccountRollover(allocator, &args) catch |err| {
                            Cmd.printAccountRolloverUsage(programName);
                            return err;
                        };
                    } else if (std.mem.eql(u8, accountOp, "update")) {
                        break :blk Cmd.parseAccountUpdate(allocator, &args) catch |err| {
                            Cmd.printAccountUpdateUsage(programName);
                            return err;
                        };
                    } else {
                        Cmd.printAccountUsage(programName);
                        return error.unk;
                    }
                } else {
                    Cmd.printAccountUsage(programName);
                    return error.unk;
                }
            }
            Cmd.printUsage(programName);
            return error.unk;
        } else {
            Cmd.printUsage(programName);
            return error.unk;
        };

        return .{
            .argIter = args,
            .command = command,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Cmd) void {
        switch (self.command) {
            inline .CreateAccountFromKeyFile, .AccountUpdate => |v| {
                if (v.contact != null) self.allocator.free(v.contact.?);
            },
            .AccountDetails, .DeactivateAccount, .AccountKeyRollover => {},
        }
        self.argIter.deinit();
    }
};
