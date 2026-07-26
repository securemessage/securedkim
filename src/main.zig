const std = @import("std");

pub const canon = @import("canon.zig");
pub const dkim = @import("dkim.zig");
pub const verify = @import("verify.zig");
pub const sign = @import("sign.zig");
pub const keytable = @import("keytable.zig");

pub fn main() !void {
    std.log.info("SecureDKIM - not yet implemented", .{});
}

// Pull in all module tests
test {
    _ = canon;
    _ = dkim;
    _ = verify;
    _ = sign;
    _ = keytable;
}
