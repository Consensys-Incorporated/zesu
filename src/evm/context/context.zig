const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const database = @import("database");
const BlockEnv = @import("block.zig").BlockEnv;
const TxEnv = @import("tx.zig").TxEnv;
const CfgEnv = @import("cfg.zig").CfgEnv;
const Journal = @import("journal.zig").Journal;
const LocalContext = @import("local.zig").LocalContext;

/// Context error type
pub const ContextError = enum {
    ok,
    database_error,
    execution_error,
    gas_error,
    stack_error,
    memory_error,
    invalid_opcode,
    invalid_jump,
    invalid_call,
    invalid_return,
    invalid_create,
    invalid_selfdestruct,
    invalid_log,
    invalid_storage,
    invalid_balance,
    invalid_nonce,
    invalid_code,
    invalid_address,
    invalid_data,
    invalid_gas,
    invalid_value,
    invalid_depth,
    invalid_static,
    invalid_access,
    invalid_warmth,
    invalid_cold,
    invalid_hot,
    invalid_touched,
    invalid_created,
    invalid_destroyed,
    invalid_reverted,
    invalid_committed,
    invalid_discarded,
    invalid_finalized,
    invalid_checkpoint,
    invalid_revert,
    invalid_commit,
    invalid_transfer,
    invalid_refund,
    invalid_cost,
    invalid_limit,
    invalid_cap,
    invalid_size,
    invalid_length,
    invalid_offset,
    invalid_index,
    invalid_key,
    invalid_hash,
    invalid_signature,
    invalid_authorization,
    invalid_permission,
    invalid_authority,
    invalid_delegation,
    invalid_proxy,
    invalid_implementation,
    invalid_interface,
    invalid_abi,
    invalid_selector,
    invalid_calldata,
    invalid_returndata,
    invalid_event,
    invalid_topic,
    invalid_logs,
    invalid_bloom,
    invalid_receipt,
    invalid_transaction,
    invalid_block,
    invalid_header,
    invalid_body,
    invalid_state,
    invalid_account,
    invalid_code_hash,
    invalid_storage_root,
    invalid_state_root,
    invalid_receipt_root,
    invalid_transactions_root,
    invalid_uncles_hash,
    invalid_mix_hash,
    invalid_nonce_value,
    invalid_difficulty,
    invalid_timestamp,
    invalid_gas_limit,
    invalid_gas_used,
    invalid_base_fee,
    invalid_extra_data,
    invalid_bloom_filter,
    invalid_logs_bloom,
    invalid_receipts_bloom,
    invalid_transactions_bloom,
    invalid_uncles_bloom,
    invalid_state_bloom,
    invalid_storage_bloom,
    invalid_account_bloom,
    invalid_balance_bloom,
    invalid_nonce_bloom,
    invalid_code_bloom,
    invalid_code_hash_bloom,
    invalid_storage_root_bloom,
    invalid_state_root_bloom,
    invalid_receipt_root_bloom,
    invalid_transactions_root_bloom,
    invalid_uncles_hash_bloom,
    invalid_mix_hash_bloom,
    invalid_nonce_value_bloom,
    invalid_difficulty_bloom,
    invalid_timestamp_bloom,
    invalid_gas_limit_bloom,
    invalid_gas_used_bloom,
    invalid_base_fee_bloom,
    invalid_extra_data_bloom,
};

/// EVM context parameterised over the database type.
///
/// DB must implement `basic`, `codeByHash`, `storage` and `blockHash`. Optional
/// hooks (`notifyCodeDeployed`, `hasNonZeroStorageForAddress`) are detected with
/// `@hasDecl` in the Journal wrappers and skipped when absent.
pub fn Context(comptime DB: type) type {
    return struct {
        /// Exposes the DB type so callers can extract it via @TypeOf(ctx.*).DatabaseType.
        pub const DatabaseType = DB;
        /// Block information.
        block: BlockEnv,
        /// Transaction information.
        tx: TxEnv,
        /// Configurations.
        cfg: CfgEnv,
        /// EVM State with journaling support and database.
        journaled_state: Journal(DB),
        /// Unused chain-specific slot.
        chain: void,
        /// Local context that is filled by execution.
        local: LocalContext,
        /// Error that happened during execution.
        ctx_error: ContextError,

        pub fn new(database_param: DB, spec: primitives.SpecId) @This() {
            var journaled_state = Journal(DB).new(database_param);
            journaled_state.setSpecId(spec);
            return .{
                .tx = TxEnv.default(),
                .block = BlockEnv.default(),
                .cfg = CfgEnv.newWithSpec(spec),
                .local = LocalContext.default(),
                .journaled_state = journaled_state,
                .chain = {},
                .ctx_error = ContextError.ok,
            };
        }

        /// Creates a new context with a new journal (same DB type).
        pub fn withNewJournal(self: @This(), new_journal_param: Journal(DB)) @This() {
            var new_journal = new_journal_param;
            new_journal.setSpecId(self.cfg.spec());
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = new_journal,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Creates a new context with a different database type.
        pub fn withDb(self: @This(), database_param: anytype) Context(@TypeOf(database_param)) {
            const NewDB = @TypeOf(database_param);
            const spec = self.cfg.spec();
            var journaled_state = Journal(NewDB).new(database_param);
            journaled_state.setSpecId(spec);
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Creates a new context wrapping a `DatabaseRef` implementation.
        pub fn withRefDb(self: @This(), db_ref: anytype) Context(database.WrapDatabaseRef(@TypeOf(db_ref))) {
            const Wrapped = database.WrapDatabaseRef(@TypeOf(db_ref));
            const spec = self.cfg.spec();
            var journaled_state = Journal(Wrapped).new(Wrapped.init(db_ref));
            journaled_state.setSpecId(spec);
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Returns a copy with `block` replaced.
        pub fn withBlock(self: @This(), block: BlockEnv) @This() {
            return .{
                .tx = self.tx,
                .block = block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Returns a copy with `tx` replaced.
        pub fn withTx(self: @This(), tx: TxEnv) @This() {
            return .{
                .tx = tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Returns a copy with `chain` replaced.
        pub fn withChain(self: @This(), chain: anytype) @This() {
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = chain,
                .ctx_error = ContextError.ok,
            };
        }

        pub fn withCfg(self: @This(), cfg: CfgEnv) @This() {
            var result = @This(){
                .tx = self.tx,
                .block = self.block,
                .cfg = cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
            result.journaled_state.setSpecId(cfg.spec());
            return result;
        }

        /// Returns a copy with `local` replaced.
        pub fn withLocal(self: @This(), local: LocalContext) @This() {
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context configuration.
        pub fn modifyCfgChained(self: @This(), f: fn (*CfgEnv) void) @This() {
            var new_cfg = self.cfg;
            f(&new_cfg);
            var result = @This(){
                .tx = self.tx,
                .block = self.block,
                .cfg = new_cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
            result.journaled_state.setSpecId(new_cfg.spec());
            return result;
        }

        /// Modifies the context block.
        pub fn modifyBlockChained(self: @This(), f: fn (*BlockEnv) void) @This() {
            var new_block = self.block;
            f(&new_block);
            return .{
                .tx = self.tx,
                .block = new_block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context transaction.
        pub fn modifyTxChained(self: @This(), f: fn (*TxEnv) void) @This() {
            var new_tx = self.tx;
            f(&new_tx);
            return .{
                .tx = new_tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context chain.
        pub fn modifyChainChained(self: @This(), f: fn (*@TypeOf(self.chain)) void) @This() {
            var new_chain = self.chain;
            f(&new_chain);
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = new_chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context database.
        pub fn modifyDbChained(self: @This(), f: fn (*DB) void) @This() {
            f(&self.journaled_state.database);
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context journal.
        pub fn modifyJournalChained(self: @This(), f: fn (*Journal(DB)) void) @This() {
            f(&self.journaled_state);
            return .{
                .tx = self.tx,
                .block = self.block,
                .cfg = self.cfg,
                .journaled_state = self.journaled_state,
                .local = self.local,
                .chain = self.chain,
                .ctx_error = ContextError.ok,
            };
        }

        /// Modifies the context block.
        pub fn modifyBlock(self: *@This(), f: fn (*BlockEnv) void) void {
            f(&self.block);
        }

        /// Modifies the context transaction.
        pub fn modifyTx(self: *@This(), f: fn (*TxEnv) void) void {
            f(&self.tx);
        }

        /// Modifies the context configuration.
        pub fn modifyCfg(self: *@This(), f: fn (*CfgEnv) void) void {
            f(&self.cfg);
            self.journaled_state.setSpecId(self.cfg.spec());
        }

        /// Modifies the context chain.
        pub fn modifyChain(self: *@This(), f: fn (*@TypeOf(self.chain)) void) void {
            f(&self.chain);
        }

        /// Modifies the context database.
        pub fn modifyDb(self: *@This(), f: fn (*DB) void) void {
            f(&self.journaled_state.database);
        }

        /// Modifies the context journal.
        pub fn modifyJournal(self: *@This(), f: fn (*Journal(DB)) void) void {
            f(&self.journaled_state);
        }

        /// Modifies the local context.
        pub fn modifyLocal(self: *@This(), f: fn (*LocalContext) void) void {
            f(&self.local);
        }

        /// Set transaction
        pub fn setTx(self: *@This(), tx: TxEnv) void {
            self.tx = tx;
        }

        /// Set block
        pub fn setBlock(self: *@This(), block: BlockEnv) void {
            self.block = block;
        }

        /// Get all context components
        pub fn all(self: @This()) struct { BlockEnv, TxEnv, CfgEnv, *const DB, Journal(DB), void, LocalContext } {
            return .{
                self.block,
                self.tx,
                self.cfg,
                &self.journaled_state.database,
                self.journaled_state,
                self.chain,
                self.local,
            };
        }

        /// Get all context components mutably
        pub fn getAllMut(self: *@This()) struct { BlockEnv, TxEnv, CfgEnv, *Journal(DB), *void, *LocalContext } {
            return .{
                self.block,
                self.tx,
                self.cfg,
                &self.journaled_state,
                &self.chain,
                &self.local,
            };
        }

        /// Get error
        pub fn getError(self: *@This()) *ContextError {
            return &self.ctx_error;
        }

        /// Get block
        pub fn getBlock(self: @This()) BlockEnv {
            return self.block;
        }

        /// Get transaction
        pub fn getTx(self: @This()) TxEnv {
            return self.tx;
        }

        /// Get configuration
        pub fn getCfg(self: @This()) CfgEnv {
            return self.cfg;
        }

        /// Get database
        pub fn db(self: @This()) *const DB {
            return &self.journaled_state.database;
        }

        /// Get database mutably
        pub fn getDb(self: *@This()) *DB {
            return &self.journaled_state.database;
        }

        /// Get journal
        pub fn getJournal(self: @This()) Journal(DB) {
            return self.journaled_state;
        }

        /// Get journal mutably
        pub fn getJournalMut(self: *@This()) *Journal(DB) {
            return &self.journaled_state;
        }

        /// Get chain
        pub fn getChain(self: @This()) @TypeOf(self.chain) {
            return self.chain;
        }

        /// Get chain mutably
        pub fn getChainMut(self: *@This()) *@TypeOf(self.chain) {
            return &self.chain;
        }

        /// Get local context
        pub fn getLocal(self: @This()) LocalContext {
            return self.local;
        }

        /// Get local context mutably
        pub fn getLocalMut(self: *@This()) *LocalContext {
            return &self.local;
        }

        // Block methods

        pub fn basefee(self: @This()) primitives.U256 {
            return @as(primitives.U256, self.block.basefee());
        }

        pub fn blobGasprice(self: @This()) primitives.U256 {
            return @as(primitives.U256, self.block.blobExcessGasAndPrice().?.blobGasprice());
        }

        pub fn gasLimit(self: @This()) primitives.U256 {
            return @as(primitives.U256, self.block.gasLimit());
        }

        pub fn difficulty(self: @This()) primitives.U256 {
            return self.block.difficulty();
        }

        pub fn prevrandao(self: @This()) ?primitives.U256 {
            return if (self.block.prevrandao()) |prev_randao| primitives.U256.fromBytes(prev_randao) else null;
        }

        pub fn blockNumber(self: @This()) primitives.U256 {
            return self.block.number();
        }

        pub fn timestamp(self: @This()) primitives.U256 {
            return self.block.timestamp();
        }

        pub fn beneficiary(self: @This()) primitives.Address {
            return self.block.beneficiary();
        }

        pub fn chainId(self: @This()) primitives.U256 {
            return @as(primitives.U256, self.cfg.chainId());
        }

        // Transaction methods

        pub fn effectiveGasPrice(self: @This()) primitives.U256 {
            const base_fee = self.block.basefee();
            return primitives.U256.fromU128(self.tx.effectiveGasPrice(base_fee));
        }

        pub fn caller(self: @This()) primitives.Address {
            return self.tx.caller();
        }

        pub fn blobHash(self: @This(), number: usize) ?primitives.U256 {
            const tx = self.tx;
            if (tx.txType() != @intFromEnum(TxEnv.TransactionType.Eip4844)) {
                return null;
            }
            const blob_hashes = tx.blobVersionedHashes();
            if (number < blob_hashes.len) {
                return primitives.U256.fromBytes(blob_hashes[number]);
            }
            return null;
        }

        // Config methods

        pub fn maxInitcodeSize(self: @This()) usize {
            return self.cfg.maxInitcodeSize();
        }

        // Database methods

        pub fn blockHash(self: *@This(), requested_number: u64) ?primitives.Hash {
            // BLOCKHASH is only valid for the last BLOCK_HASH_HISTORY (256) blocks.
            // Requests for the current block or future blocks, or blocks older than 256
            // blocks ago, must return zero per the Yellow Paper.
            const current: u64 = @intCast(self.block.number);
            if (requested_number >= current) return [_]u8{0} ** 32;
            if (current - requested_number > primitives.BLOCK_HASH_HISTORY) return [_]u8{0} ** 32;
            return self.journaled_state.database.blockHash(requested_number) catch {
                self.ctx_error = ContextError.database_error;
                return null;
            };
        }

        // Journal methods

        /// Gets the transient storage value of `address` at `index`.
        pub fn tload(self: *@This(), address: primitives.Address, index: primitives.StorageKey) primitives.StorageValue {
            return self.journaled_state.tload(address, index);
        }

        /// Sets the transient storage value of `address` at `index`.
        pub fn tstore(self: *@This(), address: primitives.Address, index: primitives.StorageKey, value: primitives.StorageValue) void {
            self.journaled_state.tstore(address, index, value);
        }

        /// Emits a log owned by `address` with given `LogData`.
        pub fn log(self: *@This(), log_entry: primitives.Log) void {
            self.journaled_state.log(log_entry);
        }

        /// Marks `address` to be deleted, with funds transferred to `target`.
        pub fn selfdestruct(self: *@This(), address: primitives.Address, target: primitives.Address) ?Journal(DB).StateLoad(Journal(DB).SelfDestructResult) {
            return self.journaled_state.selfdestruct(address, target) catch {
                self.ctx_error = ContextError.database_error;
                return null;
            };
        }

        pub fn sstoreSkipColdLoad(self: *@This(), address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue, skip_cold_load: bool) Journal(DB).StateLoad(Journal(DB).SStoreResult) {
            return self.journaled_state.sstoreSkipColdLoad(address, key, value, skip_cold_load) catch {
                self.ctx_error = ContextError.database_error;
                return Journal(DB).StateLoad.new(Journal(DB).SStoreResult{
                    .original_value = @as(primitives.StorageValue, 0),
                    .present_value = @as(primitives.StorageValue, 0),
                    .new_value = value,
                }, false);
            };
        }

        pub fn sloadSkipColdLoad(self: *@This(), address: primitives.Address, key: primitives.StorageKey, skip_cold_load: bool) Journal(DB).StateLoad(primitives.StorageValue) {
            return self.journaled_state.sloadSkipColdLoad(address, key, skip_cold_load) catch {
                self.ctx_error = ContextError.database_error;
                return Journal(DB).StateLoad.new(@as(primitives.StorageValue, 0), false);
            };
        }

        pub fn loadAccountInfoSkipColdLoad(self: *@This(), address: primitives.Address, load_code: bool, skip_cold_load: bool) Journal(DB).AccountInfoLoad {
            return self.journaled_state.loadAccountInfoSkipColdLoad(address, load_code, skip_cold_load) catch {
                self.ctx_error = ContextError.database_error;
                return Journal(DB).AccountInfoLoad.new(&state.AccountInfo.default(), false, true);
            };
        }
    };
}

/// Context over `InMemoryDB`, used by tests and the `Evm` alias. The stateless
/// executor uses `Context(WitnessDatabase)`.
pub const DefaultContext = Context(database.InMemoryDB);
