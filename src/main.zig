const std = @import("std");
const log = @import("./log.zig");
const http = @import("./http.zig");
const crypto = @import("./crypto.zig");

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

pub fn main() !u8 {
    defer http.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    //var out = try http.send_query(allocator);
    //defer allocator.free(out);

    log.stdout.print("generating RSA-2048");
    var rsa = try crypto.Key.generate(.{ .RSA = 2048 });

    var sign = try rsa.sign(allocator, "siema");
    defer allocator.free(sign);

    log.stdout.printf("signature: {x}", .{std.fmt.fmtSliceHexLower(sign)});

    log.stdout.print("generating ECDSA P256");
    var ecdsa = try crypto.Key.generate(.{ .ECDSA = .P256 });
    _ = ecdsa;

    var pem = try std.fs.cwd().readFileAlloc(allocator, "./file.pem", 11111111111);
    defer allocator.free(pem);

    var key = try crypto.Key.from_pem(pem);
    log.stderr.printf("key type: {}", .{key.type});

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
