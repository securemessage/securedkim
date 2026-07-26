const std = @import("std");

pub const canon = @import("canon.zig");
pub const dkim = @import("dkim.zig");
pub const verify = @import("verify.zig");

pub fn main() !void {
    std.log.info("SecureDKIM - not yet implemented", .{});
}

// Pull in all module tests
test {
    _ = canon;
    _ = dkim;
    _ = verify;
}
