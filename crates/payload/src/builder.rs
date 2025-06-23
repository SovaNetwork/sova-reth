use std::sync::Arc;

use alloy_consensus::{Transaction, Typed2718};
use alloy_eips::{eip2718::Encodable2718, Decodable2718};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, Bytes, B256, U256,
};
use alloy_rlp::{BytesMut, Encodable};
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_rpc_types_engine::{PayloadAttributes, PayloadId};
use alloy_sol_macro::sol;
use alloy_sol_types::SolCall;
use op_alloy_consensus::{TxDeposit, UpgradeDepositSource};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, BuildOutcomeKind, MissingPayloadBehaviour,
    PayloadBuilder, PayloadConfig,
};
use reth_chain_state::{ExecutedBlock, ExecutedBlockWithTrieUpdates};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_errors::{BlockExecutionError, BlockValidationError, RethError};
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome, BlockExecutor},
    ConfigureEvm, Database, Evm,
};
use reth_execution_types::ExecutionOutcome;
use reth_optimism_evm::OpNextBlockEnvAttributes;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::{
    txpool::OpPooledTx, OpBuiltPayload, OpPayloadAttributes, OpPayloadBuilderAttributes,
};
use reth_optimism_payload_builder::{
    builder::{ExecutionInfo, OpPayloadTransactions},
    config::{OpBuilderConfig, OpDAConfig},
    error::OpPayloadBuilderError,
    OpPayloadPrimitives,
};
use reth_optimism_primitives::transaction::OpTransaction;
use reth_optimism_txpool::interop::{is_valid_interop, MaybeInteropTransaction};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_payload_util::{NoopPayloadTransactions, PayloadTransactions};
use reth_primitives_traits::{NodePrimitives, SealedHeader, SignedTransaction, TxTy};
use reth_provider::{StateProvider, StateProviderFactory};
use reth_revm::{
    cancelled::CancelOnDrop,
    database::StateProviderDatabase,
    db::{State, TransitionAccount},
    witness::ExecutionWitnessRecord,
    DatabaseCommit,
};
use reth_storage_api::errors::ProviderError;
use reth_tracing::tracing::{debug, trace, warn};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction, TransactionPool};

use revm::{
    context::{Block, BlockEnv},
    state::Account,
};

use sova_chainspec::{L1_BLOCK_CONTRACT_ADDRESS, L1_BLOCK_CONTRACT_CALLER};
use sova_cli::SovaConfig;
use sova_evm::{BitcoinClient, MyEvmConfig, SovaL1BlockInfo, WithInspector};

sol!(
    function setBitcoinBlockData(
        uint64 _blockHeight,
        bytes32 _blockHash
    );
);

/// Sova payload builder that extends the Optimism payload builder with Bitcoin integrations
#[derive(Debug, Clone)]
pub struct SovaPayloadBuilder<Pool, Client, Evm = MyEvmConfig, Txs = ()> {
    /// The rollup's compute pending block configuration option.
    // TODO(clabby): Implement this feature.
    pub compute_pending_block: bool,
    /// The type responsible for creating the evm.
    pub evm_config: Evm,
    /// Transaction pool.
    pub pool: Pool,
    /// Node client.
    pub client: Client,
    /// Ethereum builder configuration.
    pub config: OpBuilderConfig,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
    /// Sova configuration for Bitcoin integration
    pub sova_config: SovaConfig,
    /// Bitcoin client for bitcoin core rpc calls
    pub bitcoin_client: Arc<BitcoinClient>,
}

impl<Pool, Client, Evm> SovaPayloadBuilder<Pool, Client, Evm> {
    /// `SovaPayloadBuilder` constructor with Sova and Bitcoin integration.
    pub fn new(pool: Pool, client: Client, evm_config: Evm) -> Self {
        Self::with_builder_config(pool, client, evm_config, Default::default())
    }

    /// Configures the builder with the given [`OpBuilderConfig`].
    pub fn with_builder_config(
        pool: Pool,
        client: Client,
        evm_config: Evm,
        config: OpBuilderConfig,
    ) -> Self {
        Self {
            pool,
            client,
            compute_pending_block: true,
            evm_config,
            config,
            best_transactions: (),
            sova_config: SovaConfig::default(),
            bitcoin_client: Arc::new(BitcoinClient::default()),
        }
    }

    /// Configures the `SovaPayloadBuilder` builder with Bitcoin integrations.
    pub fn with_sova_integration(
        mut self,
        sova_config: SovaConfig,
        bitcoin_client: Arc<BitcoinClient>,
    ) -> Self {
        self.sova_config = sova_config;
        self.bitcoin_client = bitcoin_client;
        self
    }
}

impl<Pool, Client, Evm, Txs> SovaPayloadBuilder<Pool, Client, Evm, Txs> {
    /// Sets the rollup's compute pending block configuration option.
    pub const fn set_compute_pending_block(mut self, compute_pending_block: bool) -> Self {
        self.compute_pending_block = compute_pending_block;
        self
    }

    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(
        self,
        best_transactions: T,
    ) -> SovaPayloadBuilder<Pool, Client, Evm, T> {
        let Self {
            pool,
            client,
            compute_pending_block,
            evm_config,
            config,
            sova_config,
            bitcoin_client,
            ..
        } = self;
        SovaPayloadBuilder {
            pool,
            client,
            compute_pending_block,
            evm_config,
            best_transactions,
            config,
            sova_config,
            bitcoin_client,
        }
    }

    /// Enables the rollup's compute pending block configuration option.
    pub const fn compute_pending_block(self) -> Self {
        self.set_compute_pending_block(true)
    }

    /// Returns the rollup's compute pending block configuration option.
    pub const fn is_compute_pending_block(&self) -> bool {
        self.compute_pending_block
    }
}

impl<Pool, Client, Evm, N, T> SovaPayloadBuilder<Pool, Client, Evm, T>
where
    Pool: TransactionPool<Transaction: OpPooledTx<Consensus = N::SignedTx>>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthChainSpec + OpHardforks>,
    N: OpPayloadPrimitives,
    Evm: ConfigureEvm<Primitives = N, NextBlockEnvCtx = OpNextBlockEnvAttributes> + WithInspector,
{
    /// Constructs an Optimism payload from the transactions sent via the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Optimism client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    ///
    /// NOTE(powvt): This implementation of the Optimism PayloadBuilder includes some Sova
    /// specific differences. The primary differences are applying the revert state changes
    /// from the sentinel cache and also applying the Sova Bitcoin context
    /// transactions (SovaL1Block).
    fn build_payload<'a, Txs>(
        &self,
        args: BuildArguments<OpPayloadBuilderAttributes<N::SignedTx>, OpBuiltPayload<N>>,
        best: impl Fn(BestTransactionsAttributes) -> Txs + Send + Sync + 'a,
    ) -> Result<BuildOutcome<OpBuiltPayload<N>>, PayloadBuilderError>
    where
        Txs: PayloadTransactions<
            Transaction: PoolTransaction<Consensus = N::SignedTx> + MaybeInteropTransaction,
        >,
    {
        let BuildArguments {
            mut cached_reads,
            config,
            cancel,
            best_payload,
        } = args;

        // TODO(powvt): investigate if this can be None?
        if config.attributes.transactions.is_empty() {
            warn!(target: "payload_builder", "No sequencer txs recieved");
        }

        let mut op_payload_attrs = OpPayloadAttributes {
            payload_attributes: PayloadAttributes {
                timestamp: config.attributes.timestamp(),
                prev_randao: config.attributes.prev_randao(),
                suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
                withdrawals: Some(config.attributes.withdrawals().to_vec()),
                parent_beacon_block_root: config.attributes.parent_beacon_block_root(),
            },
            // TODO(powvt): smae comment as above, can we do Some() here safely?
            transactions: Some(
                config
                    .attributes
                    .transactions
                    .iter()
                    .map(|tx| tx.encoded_bytes().clone())
                    .collect(),
            ),
            no_tx_pool: Some(config.attributes.no_tx_pool),
            gas_limit: config.attributes.gas_limit,
            eip_1559_params: config.attributes.eip_1559_params,
        };

        // Inject Bitcoin data
        if let Err(err) =
            SovaPayloadBuilder::<Pool, Client, Evm, T>::inject_bitcoin_data_to_payload_attrs(
                &self.bitcoin_client,
                &mut op_payload_attrs,
            )
        {
            warn!(target: "payload_builder", "Failed to inject Bitcoin data: {}", err);
            // Continue with payload building even if Bitcoin data injection fails
        }

        // Recreate the OpPayloadBuilderAttributes with the updated OpPayloadAttributes
        let updated_config = PayloadConfig {
            parent_header: config.parent_header.clone(),
            attributes: OpPayloadBuilderAttributes::try_new(
                config.attributes.parent(),
                op_payload_attrs,
                3, // Assuming version 3, adjust if needed
            )
            .map_err(PayloadBuilderError::other)?,
        };

        let ctx = SovaPayloadBuilderCtx {
            evm_config: self.evm_config.clone(),
            da_config: self.config.da_config.clone(),
            chain_spec: self.client.chain_spec(),
            config: updated_config,
            cancel,
            best_payload,
        };

        let builder = SovaBuilder::new(best, self.evm_config.clone());

        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;
        let state = StateProviderDatabase::new(&state_provider);
        let db = cached_reads.as_db_mut(state);

        builder
            .build(db, &state_provider, ctx)
            .map(|out| out.with_cached_reads(cached_reads))
    }

    /// Computes the witness for the payload.
    ///
    /// TODO(powvt): Deal with call to Bitcoin node here.
    /// Ideally that data is already in the attributes recieved from the sequencer.
    pub fn payload_witness(
        &self,
        parent: SealedHeader,
        attributes: OpPayloadAttributes,
    ) -> Result<ExecutionWitness, PayloadBuilderError> {
        // NOTE(powvt): NOT injecting Bitcoion data into attributes here

        let attributes = OpPayloadBuilderAttributes::try_new(parent.hash(), attributes, 3)
            .map_err(PayloadBuilderError::other)?;

        let config = PayloadConfig {
            parent_header: Arc::new(parent),
            attributes,
        };
        let ctx = SovaPayloadBuilderCtx {
            evm_config: self.evm_config.clone(),
            da_config: self.config.da_config.clone(),
            chain_spec: self.client.chain_spec(),
            config,
            cancel: Default::default(),
            best_payload: Default::default(),
        };

        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;

        let builder = SovaBuilder::new(
            |_| NoopPayloadTransactions::<Pool::Transaction>::default(),
            self.evm_config.clone(),
        );
        builder.witness(state_provider, &ctx)
    }

    pub fn update_l1_block_source() -> B256 {
        UpgradeDepositSource {
            intent: String::from("Sova: L1 Block Update"),
        }
        .source_hash()
    }

    /// Generate a deposit transaction to record Bitcoin block data
    pub fn create_bitcoin_data_deposit_tx(block_height: u64, block_hash: B256) -> Bytes {
        // Create the function call data for the setBitcoinBlockData method
        let call_data = setBitcoinBlockDataCall {
            _blockHeight: block_height,
            _blockHash: block_hash,
        };

        // Generate the ABI-encoded function call
        let input = call_data.abi_encode().into();

        // Create a system transaction
        let deposit_tx = TxDeposit {
            // Unique identifier for this deposit's source
            source_hash: Self::update_l1_block_source(),
            // Designated system account
            from: L1_BLOCK_CONTRACT_CALLER,
            // Target the L1Block contract
            to: alloy_primitives::TxKind::Call(L1_BLOCK_CONTRACT_ADDRESS),
            // Dont mint Sova
            mint: 0.into(),
            // NOTE(powvt): send SOVA to validator as a slashable reward. Challenge period of x blocks?
            value: U256::ZERO,
            // Gas limit for the call
            gas_limit: 250_000,
            // Not a system tx, post regolith this is not a thing
            is_system_transaction: false,
            // ABI-encoded function call
            input,
        };

        // Create a buffer to hold the encoded transaction
        let mut buffer = BytesMut::new();

        // Encode the transaction according to EIP-2718
        // This adds the transaction type byte (0x7E for Deposit) followed by RLP encoding
        deposit_tx.encode_2718(&mut buffer);

        // Convert to Bytes
        buffer.freeze().into()
    }

    /// Inject Bitcoin data into a new block via a deposit transaction
    pub fn inject_bitcoin_data_to_payload_attrs(
        bitcoin_client: &BitcoinClient,
        attributes: &mut OpPayloadAttributes,
    ) -> Result<(), PayloadBuilderError> {
        // Fetch the current Bitcoin block info from the Bitcoin client
        let bitcoin_block_info: SovaL1BlockInfo = match bitcoin_client.get_current_block_info() {
            Ok(info) => info,
            Err(err) => {
                warn!(target: "payload_builder", "Failed to get block info from BTC client: {}", err);
                SovaL1BlockInfo::default()
            }
        };

        // Generate the deposit transaction bytes with just height and hash
        let btc_tx_bytes = Self::create_bitcoin_data_deposit_tx(
            bitcoin_block_info.current_block_height,
            bitcoin_block_info.block_hash_six_blocks_back,
        );

        // Append the Bitcoin transaction to the existing transactions.
        if let Some(ref mut txs) = attributes.transactions {
            txs.push(btc_tx_bytes);
        } else {
            // If there are no transactions yet, create a vector with just the Bitcoin transaction
            attributes.transactions = Some(vec![btc_tx_bytes]);
        }

        debug!(
            target: "payload_builder",
            "Injected Bitcoin data: height={}, hash={:?}",
            bitcoin_block_info.current_block_height,
            bitcoin_block_info.block_hash_six_blocks_back,
        );

        Ok(())
    }
}

/// Implementation of the [`PayloadBuilder`] trait for [`SovaPayloadBuilder`].
impl<Pool, Client, Evm, N, Txs> PayloadBuilder for SovaPayloadBuilder<Pool, Client, Evm, Txs>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthChainSpec + OpHardforks> + Clone,
    N: OpPayloadPrimitives,
    Pool: TransactionPool<Transaction: OpPooledTx<Consensus = N::SignedTx>>,
    Evm: ConfigureEvm<Primitives = N, NextBlockEnvCtx = OpNextBlockEnvAttributes> + WithInspector,
    Txs: OpPayloadTransactions<Pool::Transaction>,
{
    type Attributes = OpPayloadBuilderAttributes<N::SignedTx>;
    type BuiltPayload = OpBuiltPayload<N>;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let pool = self.pool.clone();
        self.build_payload(args, |attrs| {
            self.best_transactions
                .best_transactions(pool.clone(), attrs)
        })
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        // we want to await the job that's already in progress because that should be returned as
        // is, there's no benefit in racing another job
        MissingPayloadBehaviour::AwaitInProgress
    }

    // NOTE: this should only be used for testing purposes because this doesn't have access to L1
    // system txs, hence on_missing_payload we return [MissingPayloadBehaviour::AwaitInProgress].
    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let args = BuildArguments {
            config,
            cached_reads: Default::default(),
            cancel: Default::default(),
            best_payload: None,
        };
        self.build_payload(args, |_| {
            NoopPayloadTransactions::<Pool::Transaction>::default()
        })?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// The type that builds the payload.
///
/// Payload building for Sova is composed of several steps.
/// The first steps are mandatory and defined by the protocol.
///
/// 1. First all System calls are applied.
/// 2. After canyon the forced deployed `create2deployer` must be loaded
/// 3. All sequencer transactions are executed (part of the payload attributes)
/// 4. All SovaL1Block injected transactions are applied
///
/// Depending on whether the node acts as a sequencer and is allowed to include additional
/// transactions (`no_tx_pool == false`):
/// 4. include additional transactions
///
/// And finally
/// 5. build the block: compute all roots (txs, state)
#[derive(derive_more::Debug)]
pub struct SovaBuilder<'a, Txs, Evm> {
    /// Yields the best transaction to include if transactions from the mempool are allowed.
    #[debug(skip)]
    best: Box<dyn Fn(BestTransactionsAttributes) -> Txs + 'a>,
    /// The type responsible for creating the evm.
    #[debug(skip)]
    evm_config: Evm,
}

impl<'a, Txs, Evm> SovaBuilder<'a, Txs, Evm> {
    /// Creates a new [`SovaBuilder`].
    pub fn new(
        best: impl Fn(BestTransactionsAttributes) -> Txs + Send + Sync + 'a,
        evm_config: Evm,
    ) -> Self {
        Self {
            best: Box::new(best),
            evm_config,
        }
    }
}

impl<Txs, Evm, N> SovaBuilder<'_, Txs, Evm>
where
    Evm: ConfigureEvm<Primitives = N, NextBlockEnvCtx = OpNextBlockEnvAttributes> + WithInspector,
    N: OpPayloadPrimitives,
{
    /// Builds the payload on top of the state.
    pub fn build<ChainSpec>(
        self,
        db: impl Database<Error = ProviderError>,
        state_provider: impl StateProvider,
        ctx: SovaPayloadBuilderCtx<Evm, N, ChainSpec>,
    ) -> Result<BuildOutcomeKind<OpBuiltPayload<N>>, PayloadBuilderError>
    where
        ChainSpec: EthChainSpec + OpHardforks,
        Txs: PayloadTransactions<
            Transaction: PoolTransaction<Consensus = N::SignedTx> + MaybeInteropTransaction,
        >,
    {
        let Self { best, evm_config } = self;
        debug!(target: "payload_builder", id=%ctx.payload_id(), parent_header = ?ctx.parent().hash(), parent_number = ctx.parent().number, "building new payload with Sova integration");

        let mut db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        // === SIMULATION PHASE ===

        let next_block_attributes = OpNextBlockEnvAttributes {
            timestamp: ctx.attributes().timestamp(),
            suggested_fee_recipient: ctx.attributes().suggested_fee_recipient(),
            prev_randao: ctx.attributes().prev_randao(),
            gas_limit: ctx.attributes().gas_limit.unwrap_or(ctx.parent().gas_limit),
            parent_beacon_block_root: ctx.attributes().parent_beacon_block_root(),
            extra_data: ctx.extra_data()?,
        };

        let bitcoin_tx = if let Some(last_tx) = ctx.config.attributes.transactions.last() {
            // Decode the last transaction to get the Bitcoin block info
            let bytes = last_tx.encoded_bytes();
            let mut bytes_slice: &[u8] = bytes.as_ref();
            if let Ok(info) = TxDeposit::decode_2718(&mut bytes_slice) {
                info
            } else {
                return Err(PayloadBuilderError::other(RethError::msg(
                    "Failed to decode last transaction for Bitcoin block info",
                )));
            }
        } else {
            return Err(PayloadBuilderError::other(RethError::msg(
                "No bitcoin transactions found in payload attributes",
            )));
        };

        // Get evm_env for the next block
        let evm_env = ctx
            .evm_config
            .next_evm_env(ctx.parent(), &next_block_attributes)
            .map_err(RethError::other)?;

        // Get best transaction attributes for simulation
        let sim_tx_attrs = BestTransactionsAttributes::new(
            evm_env.block_env.basefee,
            evm_env.block_env.blob_gasprice().map(|p| p as u64),
        );

        // Get best transactions for simulation
        let mut sim_txs = best(sim_tx_attrs);

        // Get inspector
        let inspector_lock = evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // Create EVM with inspector
        let mut evm =
            evm_config.evm_with_env_and_inspector(&mut db, evm_env.clone(), &mut *inspector);

        match evm.transact_system_call(
            L1_BLOCK_CONTRACT_CALLER,
            L1_BLOCK_CONTRACT_ADDRESS,
            bitcoin_tx.input,
        ) {
            Ok(_result) => {
                // Explicitly NOT committing state changes here
                // We're only using this simulation to capture reverts in the inspector
            }
            Err(_err) => {
                // we dont really care about the error here, we just want to capture the revert
            }
        };

        // Simulate transactions to surface reverts. Reverts are stored in the inspector's revert cache
        while let Some(pool_tx) = sim_txs.next(()) {
            let tx = pool_tx.into_consensus();

            match evm.transact(tx) {
                Ok(_result) => {
                    // Explicitly NOT committing state changes here
                    // We're only using this simulation to capture reverts in the inspector
                }
                Err(_err) => {
                    // we dont really care about the error here, we just want to capture the revert
                }
            };
        }

        drop(evm);

        let revert_cache: Vec<(Address, TransitionAccount)> = inspector.slot_revert_cache.clone();

        // === REVERT APPLICATION PHASE ===
        // Apply any reverts collected during simulation
        if !revert_cache.is_empty() {
            for (address, transition) in &revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;

                    // Load account from state
                    let acc = db.load_cache_account(*address).map_err(|err| {
                        warn!(target: "payload_builder",
                            parent_hash=%ctx.parent().hash(),
                            %err,
                            "failed to load account for payload"
                        );
                        PayloadBuilderError::Internal(err.into())
                    })?;

                    // Set slot in account to previous value
                    if let Some(a) = acc.account.as_mut() {
                        a.storage.insert(*slot, prev_value);
                    }

                    // Convert to revm account, mark as modified and commit it to state
                    let mut revm_acc: Account = acc
                        .account_info()
                        .ok_or(PayloadBuilderError::Internal(RethError::msg(
                            "failed to convert account to revm account",
                        )))?
                        .into();

                    revm_acc.mark_touch();

                    let mut changes: HashMap<Address, Account> = HashMap::new();
                    changes.insert(*address, revm_acc);

                    // commit to account slot changes to state
                    db.commit(changes);
                }
            }
        }

        drop(inspector);

        debug!("Payload Builder: mask applied to db");

        // === MAIN EXECUTION PHASE ===
        // Get inspector
        let inspector_lock = evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // Create EVM with inspector
        let evm = evm_config.evm_with_env_and_inspector(&mut db, evm_env, &mut *inspector);

        // Create block builder
        let blk_ctx = evm_config.context_for_next_block(ctx.parent(), next_block_attributes);
        let mut builder = evm_config.create_block_builder(evm, ctx.parent(), blk_ctx);

        // 1. apply pre-execution changes
        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        // 2. execute SovaL1Block transactions
        let mut info = ctx.execute_sequencer_transactions(&mut builder)?;

        // 3. if mem pool transactions are requested we execute them
        if !ctx.attributes().no_tx_pool {
            let exec_tx_attrs = ctx.best_transaction_attributes(builder.evm_mut().block());
            let exec_txs = best(exec_tx_attrs);

            if ctx
                .execute_best_transactions(&mut info, &mut builder, exec_txs)?
                .is_some()
            {
                warn!("Payload Builder: build cancelled");
                return Ok(BuildOutcomeKind::Cancelled);
            }

            // check if the new payload is even more valuable
            if !ctx.is_better_payload(info.total_fees) {
                // Release db
                drop(builder);

                // Release inspector
                drop(inspector);

                // can skip building the block
                return Ok(BuildOutcomeKind::Aborted {
                    fees: info.total_fees,
                });
            }
        }

        let BlockBuilderOutcome {
            execution_result,
            hashed_state,
            trie_updates,
            block,
        } = builder.finish(state_provider)?;

        debug!(
            "Payload builder: execution result receipts: {:?}",
            execution_result.receipts
        );

        // Release inspector
        drop(inspector);

        // === UPDATE SENTINEL LOCKS ===
        {
            let inspector_lock = evm_config.with_inspector();
            let mut inspector = inspector_lock.write();

            // Update sentinel locks for Bitcoin broadcasts in this block
            // locks are to be applied to the next block
            let locked_block_num: u64 = block.number + 1;
            inspector
                .update_sentinel_locks(locked_block_num)
                .map_err(|err| {
                    PayloadBuilderError::Internal(RethError::msg(format!(
                        "Payload building error: Failed to update sentinel locks: {}",
                        err
                    )))
                })?;
        }

        debug!("Payload Builder: locks updated");

        let sealed_block = Arc::new(block.sealed_block().clone());
        debug!(target: "payload_builder", id=%ctx.attributes().payload_id(), sealed_block_header = ?sealed_block.header(), "sealed built block");

        let execution_outcome = ExecutionOutcome::new(
            db.take_bundle(),
            vec![execution_result.receipts],
            block.number,
            Vec::new(),
        );

        // create the executed block data
        let executed: ExecutedBlockWithTrieUpdates<N> = ExecutedBlockWithTrieUpdates {
            block: ExecutedBlock {
                recovered_block: Arc::new(block.clone()),
                execution_output: Arc::new(execution_outcome),
                hashed_state: Arc::new(hashed_state),
            },
            trie: Arc::new(trie_updates),
        };

        let payload = OpBuiltPayload::new(
            ctx.payload_id(),
            sealed_block,
            info.total_fees,
            Some(executed),
        );

        if ctx.attributes().no_tx_pool {
            // if `no_tx_pool` is set only transactions from the payload attributes will be included
            // in the payload. In other words, the payload is deterministic and we can
            // freeze it once we've successfully built it.
            Ok(BuildOutcomeKind::Freeze(payload))
        } else {
            Ok(BuildOutcomeKind::Better { payload })
        }
    }

    /// Builds the payload and returns its [`ExecutionWitness`] based on the state after execution.
    pub fn witness<ChainSpec>(
        self,
        state_provider: impl StateProvider,
        ctx: &SovaPayloadBuilderCtx<Evm, N, ChainSpec>,
    ) -> Result<ExecutionWitness, PayloadBuilderError>
    where
        Evm: ConfigureEvm<Primitives = N, NextBlockEnvCtx = OpNextBlockEnvAttributes>,
        ChainSpec: EthChainSpec + OpHardforks,
        N: OpPayloadPrimitives,
        Txs: PayloadTransactions<Transaction: PoolTransaction<Consensus = N::SignedTx>>,
    {
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&state_provider))
            .with_bundle_update()
            .build();
        let mut builder = ctx.block_builder(&mut db)?;

        builder.apply_pre_execution_changes()?;
        ctx.execute_sequencer_transactions(&mut builder)?;
        builder.into_executor().apply_post_execution_changes()?;

        let ExecutionWitnessRecord {
            hashed_state,
            codes,
            keys,
            lowest_block_number: _,
        } = ExecutionWitnessRecord::from_executed_state(&db);
        let state = state_provider.witness(Default::default(), hashed_state)?;
        Ok(ExecutionWitness {
            state: state.into_iter().collect(),
            codes,
            keys,
            ..Default::default()
        })
    }
}

/// Container type that holds all necessities to build a new payload.
#[derive(derive_more::Debug)]
pub struct SovaPayloadBuilderCtx<Evm: ConfigureEvm, N: NodePrimitives, ChainSpec> {
    /// The type that knows how to perform system calls and configure the evm.
    pub evm_config: Evm,
    /// The DA config for the payload builder
    pub da_config: OpDAConfig,
    /// The chainspec
    pub chain_spec: Arc<ChainSpec>,
    /// How to build the payload.
    pub config: PayloadConfig<OpPayloadBuilderAttributes<TxTy<Evm::Primitives>>>,
    /// Marker to check whether the job has been cancelled.
    pub cancel: CancelOnDrop,
    /// The currently best payload.
    pub best_payload: Option<OpBuiltPayload<N>>,
}

impl<Evm, N, ChainSpec> SovaPayloadBuilderCtx<Evm, N, ChainSpec>
where
    Evm: ConfigureEvm<Primitives: OpPayloadPrimitives, NextBlockEnvCtx = OpNextBlockEnvAttributes>,
    N: OpPayloadPrimitives,
    ChainSpec: EthChainSpec + OpHardforks,
{
    /// Returns the parent block the payload will be build on.
    pub fn parent(&self) -> &SealedHeader {
        &self.config.parent_header
    }

    /// Returns the builder attributes.
    pub const fn attributes(&self) -> &OpPayloadBuilderAttributes<TxTy<Evm::Primitives>> {
        &self.config.attributes
    }

    /// Returns the extra data for the block.
    ///
    /// After holocene this extracts the extra data from the payload
    pub fn extra_data(&self) -> Result<Bytes, PayloadBuilderError> {
        if self.is_holocene_active() {
            self.attributes()
                .get_holocene_extra_data(
                    self.chain_spec.base_fee_params_at_timestamp(
                        self.attributes().payload_attributes.timestamp,
                    ),
                )
                .map_err(PayloadBuilderError::other)
        } else {
            Ok(Default::default())
        }
    }

    /// Returns the current fee settings for transactions from the mempool
    pub fn best_transaction_attributes(&self, block_env: &BlockEnv) -> BestTransactionsAttributes {
        BestTransactionsAttributes::new(
            block_env.basefee,
            block_env.blob_gasprice().map(|p| p as u64),
        )
    }

    /// Returns the unique id for this payload job.
    pub fn payload_id(&self) -> PayloadId {
        self.attributes().payload_id()
    }

    /// Returns true if holocene is active for the payload.
    pub fn is_holocene_active(&self) -> bool {
        self.chain_spec
            .is_holocene_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if the fees are higher than the previous payload.
    pub fn is_better_payload(&self, total_fees: U256) -> bool {
        is_better_payload(self.best_payload.as_ref(), total_fees)
    }

    /// Prepares a [`BlockBuilder`] for the next block.
    pub fn block_builder<'a, DB: Database>(
        &'a self,
        db: &'a mut State<DB>,
    ) -> Result<impl BlockBuilder<Primitives = Evm::Primitives> + 'a, PayloadBuilderError> {
        self.evm_config
            .builder_for_next_block(
                db,
                self.parent(),
                OpNextBlockEnvAttributes {
                    timestamp: self.attributes().timestamp(),
                    suggested_fee_recipient: self.attributes().suggested_fee_recipient(),
                    prev_randao: self.attributes().prev_randao(),
                    gas_limit: self
                        .attributes()
                        .gas_limit
                        .unwrap_or(self.parent().gas_limit),
                    parent_beacon_block_root: self.attributes().parent_beacon_block_root(),
                    extra_data: self.extra_data()?,
                },
            )
            .map_err(PayloadBuilderError::other)
    }

    /// Executes all sequencer transactions that are included in the payload attributes.
    pub fn execute_sequencer_transactions(
        &self,
        builder: &mut impl BlockBuilder<Primitives = Evm::Primitives>,
    ) -> Result<ExecutionInfo, PayloadBuilderError> {
        let mut info = ExecutionInfo::new();

        for sequencer_tx in &self.attributes().transactions {
            // A sequencer's block should never contain blob transactions.
            if sequencer_tx.value().is_eip4844() {
                return Err(PayloadBuilderError::other(
                    OpPayloadBuilderError::BlobTransactionRejected,
                ));
            }

            // Convert the transaction to a [RecoveredTx]. This is
            // purely for the purposes of utilizing the `evm_config.tx_env`` function.
            // Deposit transactions do not have signatures, so if the tx is a deposit, this
            // will just pull in its `from` address.
            let sequencer_tx = sequencer_tx
                .value()
                .try_clone_into_recovered()
                .map_err(|_| {
                    PayloadBuilderError::other(OpPayloadBuilderError::TransactionEcRecoverFailed)
                })?;

            debug!("sequencer tx {:?}", sequencer_tx);

            let gas_used = match builder.execute_transaction(sequencer_tx.clone()) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    trace!(target: "payload_builder", %error, ?sequencer_tx, "Error in sequencer transaction, skipping.");
                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            // add gas used by the transaction to cumulative gas used, before creating the receipt
            info.cumulative_gas_used += gas_used;
        }

        Ok(info)
    }

    /// Executes the given best transactions and updates the execution info.
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    pub fn execute_best_transactions(
        &self,
        info: &mut ExecutionInfo,
        builder: &mut impl BlockBuilder<Primitives = Evm::Primitives>,
        mut best_txs: impl PayloadTransactions<
            Transaction: PoolTransaction<Consensus = TxTy<Evm::Primitives>>
                             + MaybeInteropTransaction,
        >,
    ) -> Result<Option<()>, PayloadBuilderError> {
        let block_gas_limit = builder.evm_mut().block().gas_limit;
        let block_da_limit = self.da_config.max_da_block_size();
        let tx_da_limit = self.da_config.max_da_tx_size();
        let base_fee = builder.evm_mut().block().basefee;

        while let Some(tx) = best_txs.next(()) {
            let interop = tx.interop_deadline();
            let tx = tx.into_consensus();
            if info.is_tx_over_limits(tx.inner(), block_gas_limit, tx_da_limit, block_da_limit) {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // A sequencer's block should never contain blob or deposit transactions from the pool.
            if tx.is_eip4844() || tx.is_deposit() {
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // We skip invalid cross chain txs, they would be removed on the next block update in
            // the maintenance job
            if let Some(interop) = interop {
                if !is_valid_interop(interop, self.config.attributes.timestamp()) {
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                }
            }
            // check if the job was cancelled, if so we can exit early
            if self.cancel.is_cancelled() {
                return Ok(Some(()));
            }

            let gas_used = match builder.execute_transaction(tx.clone()) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                    } else {
                        // if the transaction is invalid, we can skip it and all of its
                        // descendants
                        trace!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                        best_txs.mark_invalid(tx.signer(), tx.nonce());
                    }
                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            // add gas used by the transaction to cumulative gas used, before creating the
            // receipt
            info.cumulative_gas_used += gas_used;
            info.cumulative_da_bytes_used += tx.length() as u64;

            // update add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            info.total_fees += U256::from(miner_fee) * U256::from(gas_used);
        }

        Ok(None)
    }
}
