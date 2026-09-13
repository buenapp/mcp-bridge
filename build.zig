const std = @import("std");

/// Link a distro system library by absolute path. Distro layouts differ
/// (Debian/Ubuntu multiarch vs Fedora /usr/lib64) and an explicit
/// -Dtarget skips zig's native path detection. Worse, zig silently drops
/// -lresolv on Linux hosts (it assumes libresolv is folded into glibc
/// >= 2.34 — true for res_query, but ns_initparse/ns_parserr still live
/// in libresolv.so.2), so a bare linkSystemLibrary is unreliable here.
/// Prefers the unversioned dev symlink, falls back to the versioned
/// runtime object (always present, no -dev package needed for linking),
/// and finally to plain -l (cross/sysroot cases).
const zon = @import("build.zig.zon");

/// Reported by --version; build.zig.zon .version tracks the release tag.
const version = zon.version;

fn linkDistroLib(b: *std.Build, mod: *std.Build.Module, name: []const u8, soname: []const u8) void {
    const dirs = [_][]const u8{
        "/usr/lib/x86_64-linux-gnu", // Debian/Ubuntu
        "/usr/lib64", // Fedora/RHEL
        "/usr/lib",
        "/usr/local/lib",
    };
    for (dirs) |dir| {
        const unversioned = std.fmt.allocPrint(b.allocator, "{s}/lib{s}.so", .{ dir, name }) catch @panic("oom");
        if (std.fs.cwd().access(unversioned, .{})) |_| {
            mod.addObjectFile(.{ .cwd_relative = unversioned });
            return;
        } else |_| {}
        const versioned = std.fmt.allocPrint(b.allocator, "{s}/lib{s}.so.{s}", .{ dir, name, soname }) catch @panic("oom");
        if (std.fs.cwd().access(versioned, .{})) |_| {
            mod.addObjectFile(.{ .cwd_relative = versioned });
            return;
        } else |_| {}
    }
    mod.linkSystemLibrary(name, .{});
}

/// Platform link wiring shared by the executable, the host test binary,
/// and the mcp-bridge-client module (issue #28). Previously pasted twice
/// and already drifted (native-Linux tests never got the linkDistroLib
/// path the executable needs). Downstream consumers of the module must
/// repeat this wiring on their own root module; this function is the
/// reference implementation.
fn linkPlatform(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, linux_sysroot: []const u8) void {
    if (target.result.os.tag == .windows) {
        mod.linkSystemLibrary("ws2_32", .{});
        mod.linkSystemLibrary("secur32", .{});
        mod.linkSystemLibrary("crypt32", .{});
        mod.linkSystemLibrary("dnsapi", .{});
        mod.linkSystemLibrary("kernel32", .{});
        mod.linkSystemLibrary("shell32", .{}); // ShellExecuteA (OAuth browser launch)
    } else {
        // POSIX: OpenSSL TLS backend. libc is required for @cImport and the
        // system resolver. FreeBSD has res_query/ns_* in libc; glibc needs
        // libresolv linked explicitly.
        mod.link_libc = true;
        if (target.result.os.tag == .freebsd) {
            // Link BASE OpenSSL, not ports: ports (/usr/local/lib) wins the
            // default -l search, but its trust dir (/usr/local/openssl/certs)
            // is not certctl-managed and the port may not be installed on a
            // target system. /usr/lib/libssl.so is the base linker symlink;
            // link it directly to bypass search order, and prefer base
            // headers (/usr/include) over ports headers (/usr/local/include).
            mod.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
            mod.addObjectFile(.{ .cwd_relative = "/usr/lib/libssl.so" });
            mod.addObjectFile(.{ .cwd_relative = "/usr/lib/libcrypto.so" });
        } else if (target.result.os.tag == .linux) {
            if (target.query.isNative()) {
                // NATIVE Linux build (CI runners, dev machines): use the
                // system toolchain, no glibc pin. Distro layouts differ
                // (Debian multiarch vs Fedora lib64) so link by absolute
                // path; -lresolv in particular is silently dropped by zig
                // (it assumes libresolv is folded into glibc >= 2.34 — true
                // for res_query, but ns_initparse/ns_parserr still live in
                // libresolv.so.2).
                mod.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
                mod.addSystemIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
                linkDistroLib(b, mod, "ssl", "3");
                linkDistroLib(b, mod, "crypto", "3");
                // No libresolv: dns_posix.zig uses res_query (in libc on
                // glibc >= 2.34 and FreeBSD) + a hand-rolled answer parser.
            } else {
                // CROSS build (from FreeBSD): bundled pinned glibc (its
                // abilist covers libresolv — zig drops -lresolv harmlessly)
                // plus a pinned OpenSSL sysroot (default
                // .sysroot/ubuntu-24.04, headers + libs from the distro
                // package). Link sysroot objects directly: the host's
                // /usr/local/lib otherwise wins and LLD happily links the
                // wrong-OS libssl.
                const sysroot = linux_sysroot;
                mod.addSystemIncludePath(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/include", .{sysroot}) catch @panic("oom") });
                mod.addObjectFile(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/lib/libssl.so", .{sysroot}) catch @panic("oom") });
                mod.addObjectFile(.{ .cwd_relative = std.fmt.allocPrint(b.allocator, "{s}/lib/libcrypto.so", .{sysroot}) catch @panic("oom") });
            }
        }
    }
}

pub fn build(b: *std.Build) void {
    var target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        },
    });

    // Pin glibc 2.39 for linux-gnu CROSS builds only (e.g. from FreeBSD):
    // zig then uses its bundled glibc, whose abilist provides everything
    // the sysroot OpenSSL (Ubuntu 24.04) and libresolv need. NEVER pin for
    // native Linux builds — a pinned binary mixes zig's bundled glibc with
    // the host's system libraries, which reference the host glibc's newer
    // and GLIBC_PRIVATE symbols and fail to link or run.
    if (!target.query.isNative() and target.result.os.tag == .linux and
        target.result.abi == .gnu and target.query.glibc_version == null)
    {
        var q = target.query;
        q.glibc_version = .{ .major = 2, .minor = 39, .patch = 0 };
        target = b.resolveTargetQuery(q);
    }

    const optimize = b.standardOptimizeOption(.{});

    // OpenSSL sysroot (include/ + lib/) for Linux cross builds. Declared
    // once here: zig panics on a b.option() re-declaration, and
    // linkPlatform() runs once per consumer.
    const linux_sysroot = b.option([]const u8, "linux-sysroot", "OpenSSL sysroot (include/ + lib/) for Linux cross builds") orelse ".sysroot/ubuntu-24.04";

    // The event port lives in born now; see docs in that repo for the
    // read-persistent/write-oneshot contract these call sites rely on.
    const born = b.dependency("born", .{ .target = target, .optimize = optimize });

    // Importable module (issue #28): the event-driven HTTP/TLS/DANE/SSE
    // client layer for downstream packages (UnAgent et al.). No
    // build_options plumbing — no file in the closure references it.
    const client = b.addModule("mcp-bridge-client", .{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    client.addImport("born", born.module("born"));
    linkPlatform(b, client, target, linux_sysroot);

    const exe = b.addExecutable(.{
        .name = "mcp-bridge",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("born", born.module("born"));

    const opts = b.addOptions();
    opts.addOption([]const u8, "version", version);
    exe.root_module.addOptions("build_options", opts);

    if (target.result.os.tag == .windows) {
        // Icon + version info (Windows resource script, compiled by zig's rc)
        exe.addWin32ResourceFile(.{ .file = b.path("assets/mcp-bridge.rc") });
    }
    linkPlatform(b, exe.root_module, target, linux_sysroot);

    b.installArtifact(exe);

    // Host-side unit tests (dane matcher, mcp, pkce, oauth, config).
    // oauth.zig reaches the platform TLS layer, so the host test binary
    // needs the same link setup as the executable.
    const born_host = b.dependency("born", .{ .target = b.graph.host, .optimize = optimize });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("born", born_host.module("born"));
    linkPlatform(b, tests.root_module, b.graph.host, linux_sysroot);
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests (host)");
    test_step.dependOn(&run_tests.step);
}
