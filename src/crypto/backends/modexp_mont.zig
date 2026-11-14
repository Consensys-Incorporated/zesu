//! Modular exponentiation for odd moduli on fixed-width limbs, by Montgomery multiplication: no
//! allocation and no division inside the exponentiation. Instantiated for moduli of up to
//! 4, 8, 16, 32, 64 and 128 64-bit limbs; modexp_impl.zig uses it for odd moduli and keeps the
//! general big-integer path for even and larger ones.
const std = @import("std");

/// Limb counts of the instantiated widths, smallest first.
pub const widths = [_]usize{ 4, 8, 16, 32, 64, 128 };

/// base^exp mod modulus into `output` (big-endian, `output.len == modulus.len`, already zeroed),
/// for an odd modulus whose significant bytes (`mod_trimmed`) fit in the largest width. Returns
/// false when it does not apply (even or too large), leaving `output` untouched.
pub fn modexp(base: []const u8, exp: []const u8, mod_trimmed: []const u8, output: []u8) bool {
    if (mod_trimmed.len == 0 or mod_trimmed[mod_trimmed.len - 1] & 1 == 0) return false;
    const limbs = (mod_trimmed.len + 7) / 8;
    inline for (widths) |n| {
        if (limbs <= n) {
            run(n, base, exp, mod_trimmed, output);
            return true;
        }
    }
    return false;
}

fn run(comptime n: usize, base: []const u8, exp: []const u8, mod_trimmed: []const u8, output: []u8) void {
    const Mont = Montgomery(n);
    const m = Mont.init(mod_trimmed);
    const a = m.fromBytes(base);
    const r = m.toNormal(m.pow(a, exp));
    // Big-endian into the low end of `output`.
    var i: usize = 0;
    while (i < output.len) : (i += 1) {
        const limb = i / 8;
        if (limb >= n) break;
        output[output.len - 1 - i] = @truncate(r[limb] >> @intCast((i % 8) * 8));
    }
}

fn Montgomery(comptime n: usize) type {
    return struct {
        const Self = @This();
        const Limbs = [n]u64;

        m: Limbs,
        /// -m^-1 mod 2^64.
        n0inv: u64,
        /// R^2 mod m, R = 2^(64n).
        r2: Limbs,
        /// R mod m: 1 in Montgomery form.
        one: Limbs,

        fn init(mod_be: []const u8) Self {
            var s: Self = undefined;
            s.m = limbsFromBe(mod_be);
            // Newton iteration for m[0]^-1 mod 2^64 (m odd): each step doubles the correct bits.
            var inv: u64 = 1;
            for (0..6) |_| inv *%= 2 -% s.m[0] *% inv;
            s.n0inv = 0 -% inv;

            // R mod m: start from the modulus's top bit (2^(b-1) < m for odd m > 1) and double.
            const b = bitLen(&s.m);
            var x: Limbs = @splat(0);
            if (b == 1) {
                // m == 1: everything is 0 mod 1.
                s.one = x;
                s.r2 = x;
                return s;
            }
            x[(b - 1) / 64] = @as(u64, 1) << @intCast((b - 1) % 64);
            for (0..64 * n - (b - 1)) |_| s.dblMod(&x);
            s.one = x;
            // 2 in Montgomery form, squared log2(64n) times: 2^(64n) in Montgomery form = R^2 mod m.
            s.dblMod(&x);
            for (0..std.math.log2_int(usize, 64 * n)) |_| x = s.mul(x, x);
            s.r2 = x;
            return s;
        }

        /// x = 2x mod m, for x < m.
        fn dblMod(s: *const Self, x: *Limbs) void {
            var carry: u64 = 0;
            for (x) |*l| {
                const next = l.* >> 63;
                l.* = (l.* << 1) | carry;
                carry = next;
            }
            if (carry != 0 or !lessThan(x, &s.m)) _ = sub(x, &s.m);
        }

        /// a * b * R^-1 mod m (CIOS), for a, b < m.
        fn mul(s: *const Self, a: Limbs, b: Limbs) Limbs {
            var t: [n + 2]u64 = @splat(0);
            for (0..n) |i| {
                var c: u64 = 0;
                for (0..n) |j| {
                    const p = @as(u128, a[i]) * b[j] + t[j] + c;
                    t[j] = @truncate(p);
                    c = @truncate(p >> 64);
                }
                const s1 = @as(u128, t[n]) + c;
                t[n] = @truncate(s1);
                t[n + 1] = @truncate(s1 >> 64);

                const u = t[0] *% s.n0inv;
                var p = @as(u128, u) * s.m[0] + t[0];
                c = @truncate(p >> 64);
                for (1..n) |j| {
                    p = @as(u128, u) * s.m[j] + t[j] + c;
                    t[j - 1] = @truncate(p);
                    c = @truncate(p >> 64);
                }
                const s2 = @as(u128, t[n]) + c;
                t[n - 1] = @truncate(s2);
                t[n] = t[n + 1] + @as(u64, @truncate(s2 >> 64));
            }
            var r: Limbs = t[0..n].*;
            if (t[n] != 0 or !lessThan(&r, &s.m)) _ = sub(&r, &s.m);
            return r;
        }

        /// x mod m: a big-endian number of any length.
        fn fromBytes(s: *const Self, be: []const u8) Limbs {
            // Horner over n-limb chunks, most significant first, in Montgomery form:
            // A' = A * R + chunk * R  (both computed as mul(., R^2)).
            var acc: Limbs = @splat(0);
            var end = be.len % (8 * n);
            if (end == 0) end = 8 * n;
            var start: usize = 0;
            while (start < be.len) {
                const chunk = limbsFromBe(be[start..@min(be.len, start + end)]);
                acc = s.mul(acc, s.r2);
                // chunk may exceed m: chunk * R^2 * R^-1 needs chunk < R, which holds.
                const c = s.mul(chunk, s.r2);
                acc = s.addMod(acc, c);
                start += end;
                end = 8 * n;
            }
            return acc;
        }

        fn addMod(s: *const Self, a: Limbs, b: Limbs) Limbs {
            var r = a;
            var carry: u1 = 0;
            for (&r, b) |*x, y| {
                const s1 = @addWithOverflow(x.*, y);
                const s2 = @addWithOverflow(s1[0], carry);
                x.* = s2[0];
                carry = s1[1] | s2[1];
            }
            if (carry != 0 or !lessThan(&r, &s.m)) _ = sub(&r, &s.m);
            return r;
        }

        fn toNormal(s: *const Self, a: Limbs) Limbs {
            var unit: Limbs = @splat(0);
            unit[0] = 1;
            return s.mul(a, unit);
        }

        /// a^exp in Montgomery form, exp big-endian.
        fn pow(s: *const Self, a: Limbs, exp: []const u8) Limbs {
            var e = exp;
            while (e.len > 0 and e[0] == 0) e = e[1..];
            var r = s.one;
            if (e.len == 0) return r;
            if (e.len <= 8) {
                // Short exponents (3, 65537, …): plain left-to-right binary.
                var started = false;
                for (e) |byte| {
                    var bit: u4 = 8;
                    while (bit > 0) {
                        bit -= 1;
                        if (started) r = s.mul(r, r);
                        if ((byte >> @intCast(bit)) & 1 == 1) {
                            r = if (started) s.mul(r, a) else a;
                            started = true;
                        }
                    }
                }
                return r;
            }
            // Fixed 4-bit window.
            var table: [16]Limbs = undefined;
            table[0] = s.one;
            table[1] = a;
            for (2..16) |k| table[k] = s.mul(table[k - 1], a);
            var started = false;
            for (e) |byte| {
                for ([_]u4{ @truncate(byte >> 4), @truncate(byte) }) |nib| {
                    if (started) {
                        for (0..4) |_| r = s.mul(r, r);
                        if (nib != 0) r = s.mul(r, table[nib]);
                    } else if (nib != 0) {
                        r = table[nib];
                        started = true;
                    }
                }
            }
            return r;
        }

        fn limbsFromBe(be: []const u8) Limbs {
            var out: Limbs = @splat(0);
            for (0..be.len) |i| {
                const byte = be[be.len - 1 - i];
                out[i / 8] |= @as(u64, byte) << @intCast((i % 8) * 8);
            }
            return out;
        }

        fn bitLen(x: *const Limbs) usize {
            var i: usize = n;
            while (i > 0) {
                i -= 1;
                if (x[i] != 0) return i * 64 + 64 - @clz(x[i]);
            }
            return 0;
        }

        fn lessThan(a: *const Limbs, b: *const Limbs) bool {
            var i: usize = n;
            while (i > 0) {
                i -= 1;
                if (a[i] != b[i]) return a[i] < b[i];
            }
            return false;
        }

        fn sub(a: *Limbs, b: *const Limbs) u1 {
            var borrow: u1 = 0;
            for (a, b) |*x, y| {
                const d1 = @subWithOverflow(x.*, y);
                const d2 = @subWithOverflow(d1[0], borrow);
                x.* = d2[0];
                borrow = d1[1] | d2[1];
            }
            return borrow;
        }
    };
}
