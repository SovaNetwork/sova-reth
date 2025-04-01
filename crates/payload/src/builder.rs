use std::sync::Arc;

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, U256,
};

use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec};
use reth_errors::{BlockExecutionError, BlockValidationError, RethError};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_primitives::{
    EthPrimitives, EthereumHardforks, InvalidTransactionError, TransactionSigned,
};
use reth_primitives_traits::SignedTransaction;
use reth_provider::StateProviderFactory;
use reth_revm::{
    database::StateProviderDatabase,
    db::{State, TransitionAccount},
    DatabaseCommit,
};
use reth_tracing::tracing::{debug, trace, warn};
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};

use revm::{context_interface::Block as _, state::Account};

use sova_evm::{MyEvmConfig, WithInspector};

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// Sova payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPayloadBuilder<Pool, Client, EvmConfig = MyEvmConfig> {
    /// Client providing access to node state.
    client: Client,
    /// Transaction pool.
    pool: Pool,
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: EthereumBuilderConfig,
}

impl<Pool, Client, EvmConfig> MyPayloadBuilder<Pool, Client, EvmConfig> {
    /// `MyPayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
    ) -> Self {
        Self {
            client,
            pool,
            evm_config,
            builder_config,
        }
    }
}

// Default implementation of [PayloadBuilder] for unit type
impl<Pool, Client, EvmConfig> PayloadBuilder for MyPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + WithInspector,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        default_sova_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        let args = BuildArguments::new(Default::default(), config, Default::default(), None);

        default_sova_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Constructs a Sova transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Sova client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
///
/// Similar to the execution flow all payloads are executed in two phases:
/// 1. Simulation phase: Transactions are simulated to surface reverts. Reverts are stored in the inspector's revert cache and applied to state prior to execution.
/// 2. Execution phase: The best transactions are executed. During the payload building process, if a better block is found, the payload is updated.
#[inline]
pub fn default_sova_payload<EvmConfig, Pool, Client, F>(
    evm_config: EvmConfig,
    client: Client,
    pool: Pool,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    best_txs: F,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + WithInspector,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
{
    let BuildArguments {
        mut cached_reads,
        config,
        cancel,
        best_payload,
    } = args;
    let PayloadConfig {
        parent_header,
        attributes,
    } = config;

    let chain_spec = client.chain_spec();

    let state_provider = client.state_by_block_hash(parent_header.hash())?;
    let state = StateProviderDatabase::new(&state_provider);
    let mut db = State::builder()
        .with_database(cached_reads.as_db_mut(state))
        .with_bundle_update()
        .build();

    let next_block_attributes = NextBlockEnvAttributes {
        timestamp: attributes.timestamp(),
        suggested_fee_recipient: attributes.suggested_fee_recipient(),
        prev_randao: attributes.prev_randao(),
        gas_limit: builder_config.gas_limit(parent_header.gas_limit),
        parent_beacon_block_root: attributes.parent_beacon_block_root(),
        withdrawals: Some(attributes.withdrawals().clone()),
    };

    // Get evm_env for the next block
    let evm_env = evm_config.next_evm_env(&parent_header, &next_block_attributes)
        .map_err(|e| RethError::other(e))?;

    // Get inspector
    let inspector_lock = evm_config.with_inspector();
    let mut inspector = inspector_lock.write();
    
    // Create EVM with inspector
    let mut evm = evm_config.evm_with_env_and_inspector(&mut db, evm_env.clone(), &mut *inspector);

    debug!(target: "payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    let base_fee = evm_env.block_env().basefee;

    // *** SIMULATION PHASE ***

    // Get simulation transaction iterator
    let best_txs_sim = best_txs(BestTransactionsAttributes::new(
        base_fee,
        evm_env
            .block_env
            .blob_gasprice()
            .map(|gasprice| gasprice as u64),
    ));

    // Simulate transactions to surface reverts. Reverts are stored in the inspector's revert cache
    for pool_tx in best_txs_sim {
        let tx = pool_tx.to_consensus();

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

    // apply mask to the database
    if !revert_cache.is_empty() {
        for (address, transition) in &revert_cache {
            for (slot, slot_data) in &transition.storage {
                let prev_value = slot_data.previous_or_original_value;

                // Load account from state
                let acc = db.load_cache_account(*address).map_err(|err| {
                    warn!(target: "payload_builder",
                        parent_hash=%parent_header.hash(),
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

    // *** EXECUTION PHASE ***

    // Get inspector
    let inspector_lock = evm_config.with_inspector();
    let mut inspector = inspector_lock.write();
    
    // Create EVM with inspector
    let evm = evm_config.evm_with_env_and_inspector(&mut db, evm_env, &mut *inspector);
    
    // Create block builder
    let ctx = evm_config.context_for_next_block(&parent_header, next_block_attributes);
    let mut builder = evm_config.create_block_builder(evm, &parent_header, ctx);

    let block_number = builder.evm_mut().block().number;
    let mut cumulative_gas_used = 0;
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit;

    // Create another transaction iterator for actual execution
    let mut best_txs = pool.best_transactions_with_attributes(BestTransactionsAttributes::new(
        base_fee,
        builder
            .evm_mut()
            .block()
            .blob_gasprice()
            .map(|gasprice| gasprice as u64),
    ));
    let mut total_fees = U256::ZERO;

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

    let mut block_blob_count = 0;
    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
    let max_blob_count = blob_params
        .as_ref()
        .map(|params| params.max_blob_count)
        .unwrap_or_default();

    while let Some(pool_tx) = best_txs.next() {
        // ensure we still have capacity for this transaction
        if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
            // we can't fit this transaction into the block, so we need to mark it as invalid
            // which also removes all dependent transaction from the iterator before we can
            // continue
            best_txs.mark_invalid(
                &pool_tx,
                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit),
            );
            continue;
        }

        // check if the job was cancelled, if so we can exit early
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled);
        }

        // convert tx to a signed transaction
        let tx = pool_tx.to_consensus();

        // There's only limited amount of blob space available per block, so we need to check if
        // the EIP-4844 can still fit in the block
        if let Some(blob_tx) = tx.as_eip4844() {
            let tx_blob_count = blob_tx.blob_versioned_hashes.len() as u64;

            if block_blob_count + tx_blob_count > max_blob_count {
                // we can't fit this _blob_ transaction into the block, so we mark it as
                // invalid, which removes its dependent transactions from
                // the iterator. This is similar to the gas limit condition
                // for regular transactions above.
                trace!(target: "payload_builder", tx=?tx.hash(), ?block_blob_count, "skipping blob transaction because it would exceed the max blob count per block");
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: block_blob_count + tx_blob_count,
                            permitted: max_blob_count,
                        },
                    ),
                );
                continue;
            }
        }

        let gas_used = match builder.execute_transaction(tx.clone()) {
            Ok(gas_used) => gas_used,
            Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            })) => {
                if error.is_nonce_too_low() {
                    // if the nonce is too low, we can skip this transaction
                    trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                } else {
                    // if the transaction is invalid, we can skip it and all of its
                    // descendants
                    trace!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::Consensus(
                            InvalidTransactionError::TxTypeNotSupported,
                        ),
                    );
                }
                continue;
            }
            // this is an error that we should treat as fatal for this attempt
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        };

        // add to the total blob gas used if the transaction successfully executed
        if let Some(blob_tx) = tx.as_eip4844() {
            block_blob_count += blob_tx.blob_versioned_hashes.len() as u64;

            // if we've reached the max blob count, we can skip blob txs entirely
            if block_blob_count == max_blob_count {
                best_txs.skip_blobs();
            }
        }

        // update add to total fees
        let miner_fee = tx
            .effective_tip_per_gas(base_fee)
            .expect("fee is always valid; execution succeeded");
        total_fees += U256::from(miner_fee) * U256::from(gas_used);
        cumulative_gas_used += gas_used;
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // Release db
        drop(builder);
        // can skip building the block
        return Ok(BuildOutcome::Aborted {
            fees: total_fees,
            cached_reads,
        });
    }

    let BlockBuilderOutcome {
        execution_result,
        block,
        ..
    } = builder.finish(&state_provider)?;

    // Release inspector
    drop(inspector);

    {
        let inspector_lock = evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // locks are to be applied to the next block
        let locked_block_num: u64 = block_number + 1;

        // handle locking of storage slots for any btc broadcasts in this block
        inspector
            .update_sentinel_locks(locked_block_num)
            .map_err(|err| {
                PayloadBuilderError::Internal(RethError::msg(format!(
                    "Payload building error: Failed to update sentinel locks: {}",
                    err
                )))
            })?;
    }

    let requests = chain_spec
        .is_prague_active_at_timestamp(attributes.timestamp)
        .then_some(execution_result.requests);

    // initialize empty blob sidecars at first. If cancun is active then this will
    let mut blob_sidecars = Vec::new();

    // only determine cancun fields when active
    if chain_spec.is_cancun_active_at_timestamp(attributes.timestamp) {
        // grab the blob sidecars from the executed txs
        blob_sidecars = pool
            .get_all_blobs_exact(
                block
                    .body()
                    .transactions()
                    .filter(|tx| tx.is_eip4844())
                    .map(|tx| *tx.tx_hash())
                    .collect(),
            )
            .map_err(PayloadBuilderError::other)?;
    }

    let sealed_block = Arc::new(block.sealed_block().clone());
    debug!(target: "payload_builder", id=%attributes.id, sealed_block_header = ?sealed_block.sealed_header(), "sealed built block");

    let mut payload = EthBuiltPayload::new(attributes.id, sealed_block, total_fees, requests);

    // extend the payload with the blob sidecars from the executed txs
    payload.extend_sidecars(blob_sidecars.into_iter().map(Arc::unwrap_or_clone));

    Ok(BuildOutcome::Better {
        payload,
        cached_reads,
    })
}
