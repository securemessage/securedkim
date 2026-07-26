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
}
