const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "mcp-bridge",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Icon + version info (Windows resource script, compiled by zig's rc)
    if (target.result.os.tag == .windows) {
        exe.addWin32ResourceFile(.{ .file = b.path("assets/mcp-bridge.rc") });
    }

    exe.root_module.linkSystemLibrary("ws2_32", .{});
    exe.root_module.linkSystemLibrary("secur32", .{});
    exe.root_module.linkSystemLibrary("crypt32", .{});
    exe.root_module.linkSystemLibrary("dnsapi", .{});
    exe.root_module.linkSystemLibrary("kernel32", .{});

    b.installArtifact(exe);

    // Host-side unit tests for the platform-independent modules.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests (host)");
    test_step.dependOn(&run_tests.step);
}
