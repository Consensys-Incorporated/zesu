//! A path-compressed radix trie over 20-byte Ethereum addresses.
//!
//! Exists to replace `AddressContext`-keyed HashMaps in the zkVM guest's hot BAL-tracking
//! path. A hashmap's worst-case per-operation cost is governed by how well an attacker can
//! collide the hash used to bucket it -- and the collision math never gets meaningfully
//! favorable here: log2(capacity) + 7 fingerprint bits is a small, gas-bounded target (see
//! primitives.AddressContext's docs), so no seed and no choice of hash function can make
//! constructing a colliding cluster genuinely infeasible for a block producer who always
//! knows the seed before finalizing their own block's contents.
//!
//! A trie has no hash function to collide at all. Worst-case per-operation cost is bounded
//! by the address length (20 bytes): path compression collapses long shared-prefix runs
//! (which is the only lever an attacker has -- choosing addresses that share bytes) into a
//! single comparison, so even a deliberately-adversarial address set costs at most a handful
//! of extra branch levels, never an unbounded probe chain.
//!
//! All keys are exactly 20 bytes, so -- unlike a general string trie -- no key is ever a
//! strict prefix of another: every value lives at a leaf, and no branch node carries a value.
//!
//! Nodes are individually heap-allocated (never stored by value in a resizable array), so a
//! `*V` returned by `getOrPut`/`getPtr` stays valid for the trie's lifetime, matching the
//! pointer-stability `std.HashMap` gives callers that hold a value_ptr across later inserts to
//! *other* keys. Callers are expected to pass an arena (or equivalent) allocator, as BaTracker
//! already does -- there is no per-node free; the whole trie is reclaimed at once.

const std = @import("std");

pub const Address = [20]u8;

pub fn AddressTrie(comptime V: type) type {
    return struct {
        root: ?*Node = null,
        len: usize = 0,

        const Self = @This();
        pub const Key = Address;
        const key_len = @typeInfo(Key).array.len;

        const Child = struct { byte: u8, node: *Node };

        const Node = struct {
            /// Bytes that must match exactly (memcmp) before branching or terminating.
            /// This is the path compression: a run of single-child levels a naive trie
            /// would spend one node per byte on collapses into one prefix here.
            prefix: []const u8,
            kind: union(enum) {
                leaf: V,
                branch: std.ArrayListUnmanaged(Child),
            },
        };

        pub const GetOrPutResult = struct {
            value_ptr: *V,
            found_existing: bool,
        };

        pub const empty: Self = .{};

        fn newLeaf(alloc: std.mem.Allocator, suffix: []const u8) !*Node {
            const node = try alloc.create(Node);
            node.* = .{ .prefix = try alloc.dupe(u8, suffix), .kind = .{ .leaf = undefined } };
            return node;
        }

        /// Frees every node. Only needed under an allocator that actually tracks individual
        /// allocations (a real free-list allocator, or a leak-checking one like
        /// `std.testing.allocator`); under an arena this is optional -- the bulk reclaim at
        /// the arena's own deinit already covers it, the same way `BaTracker`'s (unmanaged,
        /// arena-backed) use of this trie never calls it at all.
        pub fn deinit(self: *Self, alloc: std.mem.Allocator) void {
            if (self.root) |root| deinitNode(alloc, root);
            self.* = .empty;
        }

        /// Children are kept sorted by `.byte` so this can binary-search rather than scan
        /// linearly. Matters a lot in practice: real addresses are keccak-derived, i.e.
        /// uniformly random, so path compression can't help near the root at all -- a large
        /// trie's root routinely has all 256 possible first bytes present as direct children,
        /// and a linear scan there costs ~128 comparisons on average, every single lookup.
        /// Binary search costs at most 8. Returns the child's index if `byte` is present, or
        /// (found = false) the index it belongs at to keep the sort order, if not.
        const FindResult = struct { index: usize, found: bool };
        fn findChild(children: []const Child, byte: u8) FindResult {
            var lo: usize = 0;
            var hi: usize = children.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (children[mid].byte == byte) return .{ .index = mid, .found = true };
                if (children[mid].byte < byte) lo = mid + 1 else hi = mid;
            }
            return .{ .index = lo, .found = false };
        }

        fn deinitNode(alloc: std.mem.Allocator, node: *Node) void {
            switch (node.kind) {
                .leaf => {},
                .branch => |*children| {
                    for (children.items) |c| deinitNode(alloc, c.node);
                    children.deinit(alloc);
                },
            }
            alloc.free(node.prefix);
            alloc.destroy(node);
        }

        pub fn get(self: Self, key: Key) ?V {
            const ptr = self.getPtr(key) orelse return null;
            return ptr.*;
        }

        pub fn contains(self: Self, key: Key) bool {
            return self.getPtr(key) != null;
        }

        pub fn getPtr(self: Self, key: Key) ?*V {
            var node = self.root orelse return null;
            var depth: usize = 0;
            while (true) {
                if (!std.mem.eql(u8, node.prefix, key[depth..][0..node.prefix.len])) return null;
                depth += node.prefix.len;
                switch (node.kind) {
                    .leaf => |*v| {
                        std.debug.assert(depth == key.len);
                        return v;
                    },
                    .branch => |children| {
                        std.debug.assert(depth < key.len);
                        const want = key[depth];
                        const r = findChild(children.items, want);
                        if (!r.found) return null;
                        node = children.items[r.index].node;
                        depth += 1;
                    },
                }
            }
        }

        pub fn getOrPut(self: *Self, alloc: std.mem.Allocator, key: Key) !GetOrPutResult {
            if (self.root == null) {
                const leaf = try newLeaf(alloc, &key);
                self.root = leaf;
                self.len += 1;
                return .{ .value_ptr = &leaf.kind.leaf, .found_existing = false };
            }
            // A local mutable slot the recursion can redirect (via `slot.* = new_node`) if a
            // split happens at the very top; written back to `self.root` afterward. A split
            // at any deeper level instead redirects a `Child.node` field directly in place,
            // since that's already a persistent slot -- see insertAt.
            var root_ptr = self.root.?;
            const r = try insertAt(alloc, &root_ptr, key, 0);
            self.root = root_ptr;
            if (!r.found_existing) self.len += 1;
            return r;
        }

        pub fn put(self: *Self, alloc: std.mem.Allocator, key: Key, value: V) !void {
            const r = try self.getOrPut(alloc, key);
            r.value_ptr.* = value;
        }

        pub fn getOrPutValue(self: *Self, alloc: std.mem.Allocator, key: Key, value: V) !GetOrPutResult {
            const r = try self.getOrPut(alloc, key);
            if (!r.found_existing) r.value_ptr.* = value;
            return r;
        }

        /// Descends from `slot.*`, which sits at `depth` bytes into `key` (i.e. its `.prefix`
        /// is compared against `key[depth..]`), inserting `key` if absent. Every recursion
        /// step either matches fully and continues, or diverges partway through a prefix and
        /// splits that node -- the only two cases possible with byte-exact branching.
        ///
        /// Takes the *slot holding the pointer* (a `Child.node` field, or the caller's local
        /// standing in for `self.root`), not just the pointer, because a split must swap in a
        /// new branch node without disturbing the existing node's own memory: callers may
        /// already hold a `value_ptr` into it (e.g. from an earlier getOrPut on a different,
        /// as-yet-unrelated key that happened to share this leaf's prefix), and that pointer
        /// has to stay valid. Only `.prefix` on the existing node is shrunk in place -- `.kind`,
        /// and hence any such value_ptr, is never touched by a split.
        fn insertAt(alloc: std.mem.Allocator, slot: **Node, key: Key, depth: usize) !GetOrPutResult {
            const node = slot.*;
            const remaining = key[depth..];
            const max_common = @min(node.prefix.len, remaining.len);
            var common: usize = 0;
            while (common < max_common and node.prefix[common] == remaining[common]) : (common += 1) {}

            if (common == node.prefix.len) {
                // Full prefix matched.
                const new_depth = depth + node.prefix.len;
                switch (node.kind) {
                    .leaf => |*v| {
                        std.debug.assert(new_depth == key.len);
                        return .{ .value_ptr = v, .found_existing = true };
                    },
                    .branch => |*children| {
                        std.debug.assert(new_depth < key.len);
                        const want = key[new_depth];
                        const r = findChild(children.items, want);
                        if (r.found) return insertAt(alloc, &children.items[r.index].node, key, new_depth + 1);
                        const leaf = try newLeaf(alloc, key[new_depth + 1 ..]);
                        try children.insert(alloc, r.index, .{ .byte = want, .node = leaf });
                        return .{ .value_ptr = &leaf.kind.leaf, .found_existing = false };
                    },
                }
            }

            // Partial match: `node.prefix` and `remaining` diverge at `common`. Since every
            // key is exactly 20 bytes and `max_common = min(node.prefix.len, remaining.len)`,
            // a node's own prefix can never run past the key's end, so `remaining.len >=
            // node.prefix.len` always -- meaning this divergence is a genuine byte mismatch,
            // not either side running out of bytes. `node` keeps its identity (just its
            // `.prefix` shrinks, in place, to the part after the mismatching byte) and becomes
            // one child of a brand-new branch node; the new key's suffix becomes the other.
            // The parent's slot is redirected to that new branch; `node` itself is untouched
            // apart from the prefix shrink.
            const old_branch_byte = node.prefix[common];
            // A fresh, independently-owned copy, not a reslice of node's existing buffer:
            // every node's `.prefix` must stay individually freeable (see `deinitNode`), and
            // freeing a slice that no longer starts where its allocation did is unsound.
            const old_full_prefix = node.prefix;
            node.prefix = try alloc.dupe(u8, old_full_prefix[common + 1 ..]);
            alloc.free(old_full_prefix);

            const new_branch_byte = remaining[common];
            const new_leaf = try newLeaf(alloc, remaining[common + 1 ..]);

            // Kept sorted by byte (old_branch_byte != new_branch_byte -- they diverged at
            // `common` precisely because they differ) so findChild's binary search applies.
            var children: std.ArrayListUnmanaged(Child) = .empty;
            if (old_branch_byte < new_branch_byte) {
                try children.append(alloc, .{ .byte = old_branch_byte, .node = node });
                try children.append(alloc, .{ .byte = new_branch_byte, .node = new_leaf });
            } else {
                try children.append(alloc, .{ .byte = new_branch_byte, .node = new_leaf });
                try children.append(alloc, .{ .byte = old_branch_byte, .node = node });
            }

            const new_branch = try alloc.create(Node);
            new_branch.* = .{ .prefix = try alloc.dupe(u8, remaining[0..common]), .kind = .{ .branch = children } };
            slot.* = new_branch;
            return .{ .value_ptr = &new_leaf.kind.leaf, .found_existing = false };
        }

        pub const Entry = struct { key: Key, value_ptr: *V };

        /// Depth-first walk yielding every (key, value_ptr) pair. Order is unspecified and
        /// caller-irrelevant here: every consumer in this codebase sorts before committing to
        /// output. No allocator needed: a root-to-leaf path can push at most 20 frames (each
        /// frame consumes at least one key byte -- its own branch byte -- to be reached from
        /// its parent), so a fixed-size stack sized to the key length is always enough.
        pub const Iterator = struct {
            const Frame = struct { node: *Node, depth_at_entry: usize, child_idx: usize = 0 };
            stack: [key_len]Frame = undefined,
            top: usize = 0,
            key_buf: Key = [_]u8{0} ** key_len,

            fn push(self: *@This(), node: *Node, depth_at_entry: usize) void {
                @memcpy(self.key_buf[depth_at_entry..][0..node.prefix.len], node.prefix);
                self.stack[self.top] = .{ .node = node, .depth_at_entry = depth_at_entry };
                self.top += 1;
            }

            pub fn next(self: *@This()) ?Entry {
                while (self.top > 0) {
                    const frame = &self.stack[self.top - 1];
                    const depth = frame.depth_at_entry + frame.node.prefix.len;
                    switch (frame.node.kind) {
                        .leaf => |*v| {
                            std.debug.assert(depth == key_len);
                            self.top -= 1;
                            return .{ .key = self.key_buf, .value_ptr = v };
                        },
                        .branch => |children| {
                            if (frame.child_idx >= children.items.len) {
                                self.top -= 1;
                                continue;
                            }
                            const c = children.items[frame.child_idx];
                            frame.child_idx += 1;
                            self.key_buf[depth] = c.byte;
                            self.push(c.node, depth + 1);
                        },
                    }
                }
                return null;
            }
        };

        pub fn iterator(self: *const Self) Iterator {
            var it = Iterator{};
            if (self.root) |root| it.push(root, 0);
            return it;
        }

        pub const KeyIterator = struct {
            inner: Iterator,
            pub fn next(self: *@This()) ?Key {
                const e = self.inner.next() orelse return null;
                return e.key;
            }
        };

        pub fn keyIterator(self: *const Self) KeyIterator {
            return .{ .inner = self.iterator() };
        }

        pub const ValueIterator = struct {
            inner: Iterator,
            pub fn next(self: *@This()) ?*V {
                const e = self.inner.next() orelse return null;
                return e.value_ptr;
            }
        };

        pub fn valueIterator(self: *const Self) ValueIterator {
            return .{ .inner = self.iterator() };
        }

        pub fn count(self: Self) usize {
            return self.len;
        }
    };
}

/// Thin `std.HashMap`-shaped wrapper around `AddressTrie(V)`: stores its own allocator so
/// call sites don't have to thread one through, matching how `std.HashMap` wraps
/// `HashMapUnmanaged`. `deinit`/`clearRetainingCapacity` don't free individual nodes (the
/// trie never does -- see the module doc comment); they just drop the reference, which the
/// free-list allocator these run under is designed to tolerate for a single block's
/// execution, the same way `BaTracker`'s (unmanaged) use of this trie already does.
pub fn AddressTrieManaged(comptime V: type) type {
    return struct {
        unmanaged: Unmanaged = .empty,
        allocator: std.mem.Allocator,

        const Self = @This();
        pub const Unmanaged = AddressTrie(V);
        pub const Key = Unmanaged.Key;
        pub const Entry = Unmanaged.Entry;
        pub const GetOrPutResult = Unmanaged.GetOrPutResult;
        pub const Iterator = Unmanaged.Iterator;
        pub const KeyIterator = Unmanaged.KeyIterator;
        pub const ValueIterator = Unmanaged.ValueIterator;

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            self.unmanaged.deinit(self.allocator);
        }

        pub fn clearRetainingCapacity(self: *Self) void {
            self.unmanaged.deinit(self.allocator);
        }

        pub fn get(self: Self, key: Key) ?V {
            return self.unmanaged.get(key);
        }

        pub fn getPtr(self: Self, key: Key) ?*V {
            return self.unmanaged.getPtr(key);
        }

        pub fn contains(self: Self, key: Key) bool {
            return self.unmanaged.contains(key);
        }

        pub fn getOrPut(self: *Self, key: Key) !GetOrPutResult {
            return self.unmanaged.getOrPut(self.allocator, key);
        }

        pub fn put(self: *Self, key: Key, value: V) !void {
            return self.unmanaged.put(self.allocator, key, value);
        }

        pub fn getOrPutValue(self: *Self, key: Key, value: V) !GetOrPutResult {
            return self.unmanaged.getOrPutValue(self.allocator, key, value);
        }

        pub fn iterator(self: *const Self) Iterator {
            return self.unmanaged.iterator();
        }

        pub fn keyIterator(self: *const Self) KeyIterator {
            return self.unmanaged.keyIterator();
        }

        pub fn valueIterator(self: *const Self) ValueIterator {
            return self.unmanaged.valueIterator();
        }

        pub fn count(self: Self) usize {
            return self.unmanaged.count();
        }

        /// No-op: a trie has no capacity/load-factor to pre-size against, and doesn't
        /// rehash as it grows -- nodes are created on demand regardless. Kept so call sites
        /// written against `std.HashMap`'s pre-sizing idiom don't need to change.
        pub fn ensureTotalCapacity(self: *Self, new_size: u32) !void {
            _ = self;
            _ = new_size;
        }
    };
}

// Guards against reintroducing an O(fan-out) child lookup. Real addresses are
// keccak-derived (uniformly random), so path compression can't help near the root at all --
// a trie this size routinely has all 256 possible first bytes present as direct children of
// the root, and a linear scan there would cost ~128 comparisons on average, every single
// lookup, even though nothing about that data is adversarial. A regression here wouldn't
// show up in the adversarial-shared-prefix tests above at all, since those stress the
// opposite shape (narrow, deep) -- hence a dedicated realistic-shape test.
test "branch-node lookup stays near log2(fan-out), not fan-out, under realistic random addresses" {
    const alloc = std.testing.allocator;
    var t: AddressTrie(u64) = .empty;
    var prng = std.Random.DefaultPrng.init(0xF00D);
    const rand = prng.random();

    const n = 20000;
    var addrs = try alloc.alloc([20]u8, n);
    defer alloc.free(addrs);
    for (0..n) |i| {
        rand.bytes(&addrs[i]);
        const r = try t.getOrPut(alloc, addrs[i]);
        if (!r.found_existing) r.value_ptr.* = @intCast(i);
    }
    defer t.deinit(alloc);

    // Confirm the shape this test is actually exercising: with 20,000 random addresses (our
    // own worst-case-block figure), the root should be saturated -- all 256 first-byte
    // values present. If it isn't, this test isn't testing the case that matters and should
    // be revisited rather than trusted.
    const root_fanout: usize = switch (t.root.?.kind) {
        .branch => |children| children.items.len,
        .leaf => 1,
    };
    try std.testing.expectEqual(@as(usize, 256), root_fanout);

    // With sorted children + binary search, cost per branch node is bounded by
    // log2(fan-out), not fan-out itself -- confirm via the same walk, using findChild.
    var total_compares: u64 = 0;
    var total_nodes_visited: u64 = 0;
    var max_compares_at_one_node: usize = 0;
    for (addrs) |key| {
        var node = t.root.?;
        var depth: usize = 0;
        while (true) {
            total_nodes_visited += 1;
            depth += node.prefix.len;
            switch (node.kind) {
                .leaf => break,
                .branch => |children| {
                    const want = key[depth];
                    const compares = std.math.log2_int_ceil(usize, children.items.len + 1);
                    total_compares += compares;
                    if (compares > max_compares_at_one_node) max_compares_at_one_node = compares;
                    const r = AddressTrie(u64).findChild(children.items, want);
                    node = children.items[r.index].node;
                    depth += 1;
                },
            }
        }
    }
    const avg_compares = @as(f64, @floatFromInt(total_compares)) / @as(f64, @floatFromInt(n));
    // A linear scan of a saturated 256-wide root alone would average ~128 compares; binary
    // search should land under 20 total across the whole (~3-node-deep) path. Generous
    // headroom around the measured ~16.3, not a tight bound -- this is a regression guard,
    // not a performance pin.
    try std.testing.expect(avg_compares < 20.0);
    try std.testing.expect(max_compares_at_one_node <= 9); // ceil(log2(256 + 1))
}
