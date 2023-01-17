const std = @import("std");

pub fn err(comptime fmt: []const u8) void {
    errf(fmt, .{});
}

pub fn errf(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("Error: " ++ fmt ++ "\n", args);
}
