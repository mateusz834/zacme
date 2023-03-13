const std = @import("std");
const log = @import("./log.zig");

pub const Cmd = struct {
    argIter: std.process.ArgIterator,
    allocator: std.mem.Allocator,

    command: Command,

    pub const Command = union(enum) {
        CreateAccountFromKeyFile: struct {
            file: []const u8,
            forceTosAccept: bool,
            acmeURL: ?[:0]const u8,
            contact: ?[][]const u8 = null,
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
        log.stdout.printf(" - create - create ACME account", .{});
    }

    fn printAccountCreateUsage(programName: []const u8) void {
        log.stdout.printf("Usage: {s} account create [options]", .{programName});
        log.stdout.printf("Options:", .{});
        log.stdout.printf("  --tosaccept        agree to terms of service without user interacton", .{});
        log.stdout.printf("  --contact contact  provide ACME contact information (multiple allowed)", .{});
        log.stdout.printf("  --keyfile path     PEM-encoded private key file (required)", .{});
        log.stdout.printf("  --acme url         directory URL of the ACME server (default: letsencrypt)", .{});
    }

    pub const ParseArgsError = error{
        InvalidArgs,
        WantHelp,
    } || std.mem.Allocator.Error;

    fn parseAccountCreate(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsError!Command {
        var expectValueFor: ?enum { Contact, File, ACME } = null;

        var keyFile: ?[]const u8 = null;
        var acmeURL: ?[:0]const u8 = null;
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
            .contact = if (contact.items.len == 0) null else try contact.toOwnedSlice(),
            .acmeURL = acmeURL,
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

        log.stdout.printf("Program Name: {s}", .{programName});
        return .{
            .argIter = args,
            .command = command,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Cmd) void {
        switch (self.command) {
            .CreateAccountFromKeyFile => |v| {
                if (v.contact != null) self.allocator.free(v.contact.?);
            },
        }
        self.argIter.deinit();
    }
};
