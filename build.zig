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

    if (target.result.os.tag == .windows) {
        // Icon + version info (Windows resource script, compiled by zig's rc)
        exe.addWin32ResourceFile(.{ .file = b.path("assets/mcp-bridge.rc") });

        exe.root_module.linkSystemLibrary("ws2_32", .{});
        exe.root_module.linkSystemLibrary("secur32", .{});
        exe.root_module.linkSystemLibrary("crypt32", .{});
        exe.root_module.linkSystemLibrary("dnsapi", .{});
        exe.root_module.linkSystemLibrary("kernel32", .{});
    } else {
        // POSIX: OpenSSL TLS backend. libc is required for @cImport and the
        // system resolver. FreeBSD has res_query/ns_* in libc; glibc needs
        // libresolv linked explicitly.
        exe.root_module.link_libc = true;
        if (target.result.os.tag == .freebsd) {
            // Link BASE OpenSSL, not ports: ports (/usr/local/lib) wins the
            // default -l search, but its trust dir (/usr/local/openssl/certs)
            // is not certctl-managed and the port may not be installed on a
            // target system. /usr/lib/libssl.so is the base linker symlink;
            // link it directly to bypass search order, and prefer base
            // headers (/usr/include) over ports headers (/usr/local/include).
            exe.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
            exe.root_module.addObjectFile(.{ .cwd_relative = "/usr/lib/libssl.so" });
            exe.root_module.addObjectFile(.{ .cwd_relative = "/usr/lib/libcrypto.so" });
        } else if (target.result.os.tag == .linux) {
            // OpenSSL is not part of zig's bundled glibc. Cross builds use a
            // pinned sysroot (default .sysroot/ubuntu-24.04 with include/ +
            // lib/); native Linux builds use the distro multiarch dirs
            // (explicit -Dtarget skips zig's native path detection).
            const sysroot = b.option([]const u8, "linux-sysroot", "OpenSSL sysroot (include/ + lib/) for Linux builds") orelse ".sysroot/ubuntu-24.04";
            if (std.fs.cwd().access(sysroot, .{})) |_| {
                exe.root_module.addSystemIncludePath(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/include", .{sysroot}) catch @panic("oom") });
                // Link the sysroot objects directly: zig's native search
                // dirs (/usr/local/lib on FreeBSD hosts) otherwise win and
                // LLD happily links the wrong-OS libssl.
                exe.root_module.addObjectFile(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/lib/libssl.so", .{sysroot}) catch @panic("oom") });
                exe.root_module.addObjectFile(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/lib/libcrypto.so", .{sysroot}) catch @panic("oom") });
            } else |_| {
                if (target.result.cpu.arch == .x86_64) {
                    exe.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
                    exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });
                }
                exe.root_module.linkSystemLibrary("ssl", .{});
                exe.root_module.linkSystemLibrary("crypto", .{});
            }
            // glibc >= 2.34 has res_query in libc; older needs -lresolv.
            exe.root_module.linkSystemLibrary("resolv", .{});
        }
    }

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
