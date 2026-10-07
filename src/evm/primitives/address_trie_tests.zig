const std = @import("std");
const trie_mod = @import("address_trie.zig");

const AddressTrie = trie_mod.AddressTrie;
const AddressTrieManaged = trie_mod.AddressTrieManaged;
const Address = trie_mod.Address;

test "deinit frees every node under a real (leak-checking) allocator, not just an arena" {
    // BaTracker's own (unmanaged) use of this trie relies on an arena and never calls
    // deinit -- fine there. Other consumers (e.g. WitnessDatabase.storage_root_cache) use
    // a real allocator and do call it, so deinit has to actually walk and free every node,
    // including the fresh copies split() makes of a shrunk prefix -- not just reset the
    // root to null and leave the allocator's own leak detector to find everything else.
    var t: AddressTrie(u64) = .empty;
    var prng = std.Random.DefaultPrng.init(0x1EAC);
    const rand = prng.random();
    for (0..2000) |i| {
        var addr: Address = undefined;
        rand.bytes(&addr);
        if (i > 0 and rand.uintLessThan(u8, 3) == 0) {
            // Force some splits of previously-shrunk prefixes, not just fresh inserts.
            addr[0] = 0xAA;
        }
        const r = try t.getOrPut(std.testing.allocator, addr);
        if (!r.found_existing) r.value_ptr.* = @intCast(i);
    }
    t.deinit(std.testing.allocator);
    // std.testing.allocator itself asserts no leaks remain when the test process exits;
    // reaching here without that assertion firing is the actual check.
}

test "AddressTrieManaged: std.HashMap-shaped convenience API round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var m = AddressTrieManaged(u32).init(arena.allocator());
    defer m.deinit();

    const addr: Address = [_]u8{0x77} ** 20;
    try std.testing.expect(!m.contains(addr));

    try m.put(addr, 42);
    try std.testing.expectEqual(@as(?u32, 42), m.get(addr));
    try std.testing.expect(m.contains(addr));
    try std.testing.expectEqual(@as(usize, 1), m.count());

    const gop = try m.getOrPutValue(addr, 999);
    try std.testing.expectEqual(@as(u32, 42), gop.value_ptr.*); // existing value untouched

    var it = m.keyIterator();
    var seen: usize = 0;
    while (it.next()) |k| {
        try std.testing.expectEqualSlices(u8, &addr, &k);
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), seen);

    m.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0), m.count());
    try std.testing.expect(!m.contains(addr));
}

test "basic getOrPut / get / contains round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var t: AddressTrie(u64) = .empty;
    const addr1: Address = [_]u8{1} ** 20;
    const addr2: Address = [_]u8{2} ** 20;

    try std.testing.expect(!t.contains(addr1));
    try std.testing.expectEqual(@as(?u64, null), t.get(addr1));

    const r1 = try t.getOrPut(a, addr1);
    try std.testing.expect(!r1.found_existing);
    r1.value_ptr.* = 111;

    const r2 = try t.getOrPut(a, addr2);
    try std.testing.expect(!r2.found_existing);
    r2.value_ptr.* = 222;

    try std.testing.expectEqual(@as(?u64, 111), t.get(addr1));
    try std.testing.expectEqual(@as(?u64, 222), t.get(addr2));
    try std.testing.expect(t.contains(addr1));
    try std.testing.expect(t.contains(addr2));

    const r1_again = try t.getOrPut(a, addr1);
    try std.testing.expect(r1_again.found_existing);
    try std.testing.expectEqual(@as(u64, 111), r1_again.value_ptr.*);
    try std.testing.expectEqual(r1.value_ptr, r1_again.value_ptr);

    try std.testing.expectEqual(@as(usize, 2), t.count());
}

test "adjacent addresses sharing a 19-byte prefix" {
    // The exact shape a linear-fold or truncation hash collided on: this now has to be
    // resolved correctly by the split logic, not by any hash at all.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var t: AddressTrie(u32) = .empty;
    const n = 4096;
    for (0..n) |i| {
        var addr: Address = [_]u8{0xAB} ** 20;
        addr[19] = @intCast(i % 256);
        addr[18] = @intCast(i / 256);
        const r = try t.getOrPut(a, addr);
        try std.testing.expect(!r.found_existing);
        r.value_ptr.* = @intCast(i);
    }
    try std.testing.expectEqual(@as(usize, n), t.count());
    for (0..n) |i| {
        var addr: Address = [_]u8{0xAB} ** 20;
        addr[19] = @intCast(i % 256);
        addr[18] = @intCast(i / 256);
        try std.testing.expectEqual(@as(?u32, @intCast(i)), t.get(addr));
    }
}

test "differential against a reference AutoHashMap over random addresses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var t: AddressTrie(u32) = .empty;
    var ref = std.AutoHashMap(Address, u32).init(std.testing.allocator);
    defer ref.deinit();

    var prng = std.Random.DefaultPrng.init(0x5EED_1234);
    const rand = prng.random();

    var addrs: [2000]Address = undefined;
    for (0..addrs.len) |i| {
        // Biased byte distribution: mostly random, but occasionally reuse a previous
        // address's bytes in part, to force real branching/splitting rather than every
        // address diverging at byte 0.
        var addr: Address = undefined;
        rand.bytes(&addr);
        if (i > 0 and rand.uintLessThan(u8, 4) == 0) {
            const src = addrs[rand.uintLessThan(usize, i)];
            const shared_len = rand.uintLessThan(usize, 20);
            @memcpy(addr[0..shared_len], src[0..shared_len]);
        }
        addrs[i] = addr;

        const val: u32 = @intCast(i);
        const tr = try t.getOrPut(a, addr);
        const gop = try ref.getOrPut(addr);
        try std.testing.expectEqual(gop.found_existing, tr.found_existing);
        if (!tr.found_existing) {
            tr.value_ptr.* = val;
            gop.value_ptr.* = val;
        }
    }

    try std.testing.expectEqual(ref.count(), t.count());

    var it = ref.iterator();
    while (it.next()) |e| {
        try std.testing.expectEqual(@as(?u32, e.value_ptr.*), t.get(e.key_ptr.*));
    }

    // And the trie shouldn't report anything the reference doesn't have.
    var seen: usize = 0;
    var tit = t.iterator();
    while (tit.next()) |e| {
        try std.testing.expectEqual(ref.get(e.key).?, e.value_ptr.*);
        seen += 1;
    }
    try std.testing.expectEqual(ref.count(), seen);
}

test "getOrPut value_ptr stays valid across later, unrelated inserts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var t: AddressTrie(u64) = .empty;
    const first: Address = [_]u8{0x11} ** 20;
    const r = try t.getOrPut(a, first);
    r.value_ptr.* = 0xDEAD_BEEF;
    const held_ptr = r.value_ptr;

    var prng = std.Random.DefaultPrng.init(0xABCD);
    const rand = prng.random();
    for (0..5000) |_| {
        var addr: Address = undefined;
        rand.bytes(&addr);
        const gop = try t.getOrPut(a, addr);
        if (!gop.found_existing) gop.value_ptr.* = 0;
    }

    try std.testing.expectEqual(@as(u64, 0xDEAD_BEEF), held_ptr.*);
    try std.testing.expectEqual(held_ptr, t.getPtr(first).?);
}

test "iterator visits every inserted key exactly once, including a shared-prefix cluster" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var t: AddressTrie(void) = .empty;
    var expect = std.AutoHashMap(Address, void).init(std.testing.allocator);
    defer expect.deinit();

    // A cluster sharing a long prefix (the adversarial shape) plus scattered random ones.
    for (0..300) |i| {
        var addr: Address = [_]u8{0x42} ** 20;
        addr[19] = @intCast(i % 256);
        addr[18] = @intCast(i / 256);
        try t.put(a, addr, {});
        try expect.put(addr, {});
    }
    var prng = std.Random.DefaultPrng.init(0x9);
    const rand = prng.random();
    for (0..300) |_| {
        var addr: Address = undefined;
        rand.bytes(&addr);
        try t.put(a, addr, {});
        try expect.put(addr, {});
    }

    var count: usize = 0;
    var it = t.keyIterator();
    while (it.next()) |k| {
        try std.testing.expect(expect.contains(k));
        count += 1;
    }
    try std.testing.expectEqual(expect.count(), count);
}
