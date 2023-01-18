const std = @import("std");

pub fn err(comptime fmt: []const u8) void {
    errf(fmt, .{});
}

pub fn errf(comptime fmt: []const u8, args: anytype) void {
    stderr.printf("Error: " ++ fmt, args);
}

pub const stderr = struct {
    pub fn print(comptime fmt: []const u8) void {
        print(fmt, .{});
    }

    pub fn printf(comptime fmt: []const u8, args: anytype) void {
        std.io.getStdErr().writer().print(fmt ++ "\n", args) catch return;
    }
};

pub const stdout = struct {
    pub fn print(comptime fmt: []const u8) void {
        print(fmt, .{});
    }

    pub fn printf(comptime fmt: []const u8, args: anytype) void {
        std.io.getStdOut().writer().print(fmt ++ "\n", args) catch return;
    }
};
