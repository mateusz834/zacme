const std = @import("std");
const log = @import("log.zig");

const curl = @cImport({
    @cInclude("curl/curl.h");
});

var handle: ?*curl.CURL = null;

pub fn deinit() void {
	if (handle != null) {
		curl.curl_easy_cleanup(handle);
		curl.curl_global_cleanup();
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

	ret = curl.curl_easy_setopt(handle, curl.CURLOPT_VERBOSE, @intCast(c_long, 1));
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl debug: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}

	ret = curl.curl_easy_setopt(handle, curl.CURLOPT_SSLVERSION, curl.CURL_SSLVERSION_TLSv1_2);
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl min TLS verison: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}

	ret = curl.curl_easy_setopt(handle, curl.CURLOPT_WRITEFUNCTION, writeCallback);
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl write function: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}

	// allow only the use of https.
	ret = curl.curl_easy_setopt(handle, curl.CURLOPT_PROTOCOLS_STR, "https");
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl write function: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}
}

pub fn send_query(allocator: std.mem.Allocator) ![]u8 {
	try init();

	var ret = curl.curl_easy_setopt(handle, curl.CURLOPT_URL, "https://google.com");
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl url: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}

	var data = writeData{.list = std.ArrayList(u8).init(allocator)};
	errdefer data.list.deinit();

	ret = curl.curl_easy_setopt(handle, curl.CURLOPT_WRITEDATA, &data);
	if (ret != curl.CURLE_OK) {
		log.errf("failed to set libcurl write data: {s}", .{curl.curl_easy_strerror(ret)});
        return error.CURLFailedSetURL;
	}

	ret = curl.curl_easy_perform(handle);

	if (data.err != null)
		return data.err.?;

	return try data.list.toOwnedSlice();
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
