const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const securemilter_dep = b.dependency("securemilter", .{
        .target = target,
        .optimize = optimize,
    });
    const securemilter_mod = securemilter_dep.module("securemilter");

    const crypto_dep = b.dependency("securemilter_crypto", .{
        .target = target,
        .optimize = optimize,
    });
    const crypto_mod = crypto_dep.module("securemilter_crypto");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "securedkim",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // securedkim-check: verify every DKIM-Signature on a message and print each
    // result. Exists so the RFC 6376 / RFC 8463 conformance suite and the dkimpy
    // differential harness can drive the shipped verifier, the way
    // securespf-check and securearc-check do.
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/check.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const check_exe = b.addExecutable(.{
        .name = "securedkim-check",
        .root_module = check_mod,
    });
    b.installArtifact(check_exe);

    // securedkim-genkey CLI tool (only needs securemilter_crypto)
    const genkey_mod = b.createModule(.{
        .root_source_file = b.path("src/genkey.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const genkey_exe = b.addExecutable(.{
        .name = "securedkim-genkey",
        .root_module = genkey_mod,
    });
    b.installArtifact(genkey_exe);

    // securedkim-testkey CLI tool (needs securemilter for DNS + securemilter_crypto for key loading)
    const testkey_mod = b.createModule(.{
        .root_source_file = b.path("src/testkey.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const testkey_exe = b.addExecutable(.{
        .name = "securedkim-testkey",
        .root_module = testkey_mod,
    });
    b.installArtifact(testkey_exe);

    const test_step = b.step("test", "Run unit tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });

    const main_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(main_tests);
    test_step.dependOn(&run_tests.step);

    // One canonical checker, shared from securemilter-lib rather than copied.
    const lint = b.addSystemCommand(&.{"sh"});
    lint.addFileArg(securemilter_dep.path("tools/check-line-limit.sh"));
    lint.addArg("src");
    lint.addArg(".line-limit-allow");
    if (b.args) |args| lint.addArgs(args);
    lint.has_side_effects = true;
    const lint_step = b.step("lint", "Fail on source files over the 400-line limit");
    lint_step.dependOn(&lint.step);
}
