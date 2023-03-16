const std = @import("std");
const log = @import("log.zig");

const curl = @cImport({
    @cInclude("curl/curl.h");
});

var handle: ?*curl.CURL = null;
var errBuf: [curl.CURL_ERROR_SIZE:0]u8 = undefined;
var verbose = true;

pub fn deinit() void {
    if (handle != null) {
        curl.curl_easy_cleanup(handle);
        curl.curl_global_cleanup();
    }
}

fn setOpt(option: curl.CURLoption, value: anytype) !void {
    var ret = curl.curl_easy_setopt(handle, option, value);
    if (ret != curl.CURLE_OK) {
        log.errf("failed to set libcurl option: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetOpt;
    }
}

fn init() !void {
    if (handle != null)
        return;

    var ret = curl.curl_global_init(curl.CURL_GLOBAL_ALL);
    if (ret != curl.CURLE_OK) {
        log.errf("failed to initialize libcurl: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLGlobalInitFailed;
    }
    errdefer curl.curl_global_cleanup();

    handle = curl.curl_easy_init() orelse {
        log.err("failed to create libcurl handle");
        return error.CURLFailedHandleInit;
    };
    errdefer curl.curl_easy_cleanup(handle);

    if (verbose)
        try setOpt(curl.CURLOPT_VERBOSE, @intCast(c_long, 1));

    // TODO:
    // RFC 8555 6.1:
    // ACME clients MUST send a User-Agent header field, in accordance with
    // [RFC7231].  This header field SHOULD include the name and version of
    // the ACME software in addition to the name and version of the
    // underlying HTTP client software.

    // TODO:
    // RFC 8555 6.1:
    // ACME clients SHOULD send an Accept-Language header field in
    // accordance with [RFC7231] to enable localization of error messages.

    // TODO:
    // RFC 8555 6.1:
    // ACME servers SHOULD follow the recommendations of [RFC7525] when
    // configuring their TLS implementations.
    // TODO: so if servers SHOULD follow this recommendations, we should
    // (by default) make sure that we are connecting to servers that
    // fulfill that recomendation, (probably only setting the cipher suites).

    try setOpt(curl.CURLOPT_SSLVERSION, curl.CURL_SSLVERSION_TLSv1_2);
    try setOpt(curl.CURLOPT_HEADERFUNCTION, headersCallback);
    try setOpt(curl.CURLOPT_WRITEFUNCTION, writeCallback);
    try setOpt(curl.CURLOPT_ERRORBUFFER, &errBuf[0]);

    // RFC 8555 6.1:
    // Each ACME function is accomplished by the client sending a sequence
    // of HTTPS requests to the server [RFC2818], carrying JSON messages
    // [RFC8259].  Use of HTTPS is REQUIRED.
    try setOpt(curl.CURLOPT_PROTOCOLS_STR, "https");
}

pub const Request = struct {
    method: Method,
    url: [:0]const u8,
    body: ?body = null,

    pub const body = struct {
        content: []const u8,
        type: Type,

        pub const Type = enum {
            JSON,

            pub fn contentTypeHeader(self: Type) [:0]const u8 {
                return switch (self) {
                    .JSON => "Content-Type: application/jose+json",
                };
            }
        };
    };

    pub const Method = enum {
        GET,
        POST,
        HEAD,

        pub fn string(self: Method) [:0]const u8 {
            return switch (self) {
                .GET => "GET",
                .POST => "POST",
                .HEAD => "HEAD",
            };
        }
    };
};

pub const Respose = struct {
    status: u64,
    headers: std.StringHashMapUnmanaged([][]const u8),
    body: []const u8,
    contentType: ContentType,

    pub const ContentType = enum { JSON, JSONProblem, Unknown };

    pub fn deinit(self: *Respose, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        deinitHashMap(&self.headers, allocator);
    }
};

fn deinitHashMap(map: *std.StringHashMapUnmanaged([][]const u8), allocator: std.mem.Allocator) void {
    var i = map.iterator();
    while (i.next()) |v| {
        for (v.value_ptr.*) |item| allocator.free(item);
        allocator.free(v.key_ptr.*);
        allocator.free(v.value_ptr.*);
    }
    map.deinit(allocator);
}

pub fn query(allocator: std.mem.Allocator, request: Request) !Respose {
    try init();
    try setOpt(curl.CURLOPT_URL, request.url.ptr);
    try setOpt(curl.CURLOPT_CUSTOMREQUEST, request.method.string().ptr);

    var headers: ?*curl.struct_curl_slist = null;
    defer if (headers != null) curl.curl_slist_free_all(headers);

    var rData: readData = undefined;
    if (request.body != null) {
        rData = readData{ .buf = request.body.?.content };
        headers = curl.curl_slist_append(headers, request.body.?.type.contentTypeHeader().ptr);
        try setOpt(curl.CURLOPT_POST, @intCast(u64, 1));
        try setOpt(curl.CURLOPT_READDATA, &rData);
        try setOpt(curl.CURLOPT_READFUNCTION, readCallback);
        try setOpt(curl.CURLOPT_POSTFIELDSIZE, rData.buf.len);
    } else {
        try setOpt(curl.CURLOPT_POST, @intCast(u64, 0));
        try setOpt(curl.CURLOPT_READDATA, @intCast(usize, 0));
        try setOpt(curl.CURLOPT_READFUNCTION, @intCast(usize, 0));
        try setOpt(curl.CURLOPT_POSTFIELDSIZE, @intCast(usize, 0));
    }

    var data = writeData{ .list = std.ArrayList(u8).init(allocator) };
    errdefer data.list.deinit();

    try setOpt(curl.CURLOPT_WRITEDATA, &data);

    var hData = headersData{ .allocator = allocator };
    errdefer deinitHashMap(&hData.headers, allocator);
    try setOpt(curl.CURLOPT_HEADERDATA, &hData);

    try setOpt(curl.CURLOPT_HTTPHEADER, headers);
    var ret = curl.curl_easy_perform(handle);
    if (ret != curl.CURLE_OK) {
        log.errf("libcurl failed while performing query: {s}", .{errBuf});
        return error.CURLPerformFailed;
    }

    if (data.err != null) {
        log.errf("failed while writing data to buffer: {}", .{data.err.?});
        return data.err.?;
    }

    if (hData.err != null) {
        log.errf("failed while writing headers to map: {}", .{hData.err.?});
        return data.err.?;
    }

    var code: c_long = undefined;
    ret = curl.curl_easy_getinfo(handle, curl.CURLINFO_RESPONSE_CODE, &code);
    if (ret != curl.CURLE_OK) {
        log.errf("failed to set libcurl option: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLPerformFailed;
    }

    var ct: [*c]const u8 = null;
    ret = curl.curl_easy_getinfo(handle, curl.CURLINFO_CONTENT_TYPE, &ct);
    if (ret != curl.CURLE_OK) {
        log.errf("failed to retreive response content type: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLPerformFailed;
    }

    var contentType: Respose.ContentType = if (ct != null) blk: {
        // TODO: (tested) this also includes attributes, handle them somehow (ignore).
        const c = std.mem.span(ct);
        break :blk if (std.ascii.eqlIgnoreCase(c, "application/json"))
            .JSON
        else if (std.ascii.eqlIgnoreCase(c, "application/problem+json"))
            .JSONProblem
        else
            .Unknown;
    } else .Unknown;

    if (verbose) {
        log.stderr.printf("{s}", .{data.list.items});
    }

    return .{
        .status = @intCast(u64, code),
        .headers = hData.headers,
        .body = try data.list.toOwnedSlice(),
        .contentType = contentType,
    };
}

const writeData = struct {
    list: std.ArrayList(u8),
    err: ?std.mem.Allocator.Error = null,
};

fn writeCallback(data: *anyopaque, _: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var usr_data = @intToPtr(*writeData, @ptrToInt(user_data));
    var typed_data = @intToPtr([*]u8, @ptrToInt(data));

    usr_data.list.appendSlice(typed_data[0..nmemb]) catch |err| {
        usr_data.err = err;
        return curl.CURL_WRITEFUNC_ERROR;
    };

    return nmemb;
}

const readData = struct { buf: []const u8 };

fn readCallback(data: *anyopaque, _: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var usr_data = @intToPtr(*readData, @ptrToInt(user_data));
    var typed_data = @intToPtr([*]u8, @ptrToInt(data))[0..nmemb];
    var copyLength = @min(nmemb, usr_data.buf.len);
    std.mem.copy(u8, typed_data, usr_data.buf[0..copyLength]);
    usr_data.buf = usr_data.buf[copyLength..];
    return @intCast(c_uint, copyLength);
}

const headersData = struct {
    headers: std.StringHashMapUnmanaged([][]const u8) = std.StringHashMapUnmanaged([][]const u8){},
    allocator: std.mem.Allocator,
    afterFirst: bool = false,
    err: ?error{ InvalidHeader, OutOfMemory } = null,
};

fn headersCallback(data: *anyopaque, _: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var usr_data = @intToPtr(*headersData, @ptrToInt(user_data));
    var header = @intToPtr([*]const u8, @ptrToInt(data))[0..nmemb];
    if (!usr_data.afterFirst) {
        usr_data.afterFirst = true;
        return nmemb;
    }
    headerCallbackErr(header, usr_data) catch |err| {
        usr_data.err = err;
        return curl.CURLE_WRITE_ERROR;
    };

    return nmemb;
}

fn headerCallbackErr(header: []const u8, usr_data: *headersData) !void {
    const allocator = usr_data.allocator;

    if (std.mem.indexOf(u8, header, ":")) |index| {
        var key = header[0..index];
        var value = header[index + 1 ..];

        // TODO: lubcurl appends newlines here for some reason
        // figure out if this is CRLF of LF.
        // and a space TODO
        value = value[1 .. value.len - 2];

        var valueAlloc = try allocator.alloc(u8, value.len);
        errdefer allocator.free(valueAlloc);
        std.mem.copy(u8, valueAlloc, value);

        if (usr_data.headers.get(key)) |v| {
            var valueSlice = try allocator.alloc([]const u8, v.len + 1);
            errdefer allocator.free(valueSlice);
            std.mem.copy([]const u8, valueSlice, v);
            valueSlice[v.len] = valueAlloc;
            try usr_data.headers.put(allocator, usr_data.headers.getKey(key).?, valueSlice);
            allocator.free(v);
        } else {
            var keyAlloc = try allocator.alloc(u8, key.len);
            errdefer allocator.free(keyAlloc);
            std.mem.copy(u8, keyAlloc, key);

            var valueSlice = try allocator.alloc([]const u8, 1);
            errdefer allocator.free(valueAlloc);
            valueSlice[0] = valueAlloc;
            try usr_data.headers.put(allocator, keyAlloc, valueSlice);
        }
    } else {
        return;
    }
}
