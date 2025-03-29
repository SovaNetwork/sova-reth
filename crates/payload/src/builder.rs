use std::sync::Arc;

use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::{
    eip4844::MAX_DATA_GAS_PER_BLOCK, eip6110, eip7685::Requests, eip7840::BlobParams,
    merge::BEACON_NONCE,
};
use alloy_primitives::{
    map::foldhash::{HashMap, HashMapExt},
    Address, U256,
};

use reth_basic_payload_builder::{
    commit_withdrawals, is_better_payload, BuildArguments, BuildOutcome, PayloadBuilder,
    PayloadConfig,
};
use reth_chain_state::ExecutedBlock;
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_errors::RethError;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{
    env::EvmEnv, system_calls::SystemCaller, ConfigureEvm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::eip6110::parse_deposits_from_receipts;
use reth_execution_types::ExecutionOutcome;
use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_primitives::{
    proofs::calculate_transaction_root, Block, BlockBody, BlockExt, EthereumHardforks,
    InvalidTransactionError, Receipt, TransactionSigned,
};
use reth_primitives_traits::SignedTransaction;
use reth_provider::StateProviderFactory;
use reth_revm::{
    database::StateProviderDatabase,
    db::{states::bundle_state::BundleRetention, State},
    primitives::{Account, BlockEnv, CfgEnvWithHandlerCfg, EVMError, EnvWithHandlerCfg, InvalidTransaction, ResultAndState, TxEnv},
    DatabaseCommit, TransitionAccount,
};
use reth_tracing::tracing::{debug, trace, warn};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError, noop::NoopTransactionPool, BestTransactions,
    BestTransactionsAttributes, PoolTransaction, TransactionPool, ValidPoolTransaction,
};

use sova_evm::{MyEvmConfig, WithInspector};

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// Sova payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPayloadBuilder<EvmConfig = MyEvmConfig> {
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: EthereumBuilderConfig,
}

impl<EvmConfig> MyPayloadBuilder<EvmConfig> {
    pub const fn new(evm_config: EvmConfig, builder_config: EthereumBuilderConfig) -> Self {
        Self {
            evm_config,
            builder_config,
        }
    }
}

impl<EvmConfig> MyPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    /// Returns the configured [`EvmEnv`] for the targeted payload
    /// (that has the `parent` as its parent).
    fn cfg_and_block_env(
        &self,
        config: &PayloadConfig<EthPayloadBuilderAttributes>,
        parent: &Header,
    ) -> Result<EvmEnv, EvmConfig::Error> {
        let next_attributes = NextBlockEnvAttributes {
            timestamp: config.attributes.timestamp(),
            suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
            prev_randao: config.attributes.prev_randao(),
            gas_limit: self.builder_config.gas_limit(parent.gas_limit),
            withdrawals: Some(config.attributes.withdrawals.clone()),
            parent_beacon_block_root: config.attributes.parent_beacon_block_root,
        };
        
        self.evm_config.next_evm_env(parent, &next_attributes)
    }
}

// Default implementation of [PayloadBuilder] for unit type
impl<EvmConfig, Pool, Client> PayloadBuilder<Pool, Client> for MyPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header, Transaction = TransactionSigned> + WithInspector,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let env = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool().clone();
        default_sova_payload(
            self.evm_config.clone(),
            self.builder_config.clone(),
            args,
            env.cfg_env,
            env.block_env,
            |attributes| pool.best_transactions_with_attributes(attributes),
        )
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        // Create BuildArguments using the builder pattern for v1.3.4
        let args = BuildArguments::builder()
            .client(client)
            .pool(NoopTransactionPool::default())
            .config(config)
            .build();

        let env = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool().clone();

        default_sova_payload(
            self.evm_config.clone(),
            self.builder_config.clone(),
            args,
            env.cfg_env,
            env.block_env,
            |attributes| pool.best_transactions_with_attributes(attributes),
        )?
        .payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Constructs a Sova transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Sova client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
///
/// Similar to the execution flow all payloads
#[inline]
pub fn default_sova_payload<EvmConfig, Pool, Client, F>(
    evm_config: EvmConfig,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<Pool, Client, EthPayloadBuilderAttributes, EthBuiltPayload>,
    initialized_cfg: CfgEnvWithHandlerCfg,
    initialized_block_env: BlockEnv,
    best_txs: F,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Header = Header, Transaction = TransactionSigned> + WithInspector,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
{
    // Extract fields using the accessor methods for v1.3.4
    let client = args.client();
    let cached_reads = args.cached_reads_mut();
    let config = args.config.clone();
    let cancel = args.cancel();
    let best_payload = args.best_payload();

    let env = EnvWithHandlerCfg::new_with_cfg_env(
        initialized_cfg.clone(),
        initialized_block_env.clone(),
        TxEnv::default(),
    );

    let chain_spec = client.chain_spec();
    let state_provider = client.state_by_block_hash(config.parent_header.hash())?;
    let state = StateProviderDatabase::new(state_provider);
    let mut db = State::builder()
        .with_database(cached_reads.as_db_mut(state))
        .with_bundle_update()
        .build();
    let PayloadConfig {
        parent_header,
        attributes,
    } = config;

    debug!(target: "payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    let block_gas_limit: u64 = initialized_block_env.gas_limit.to::<u64>();
    let base_fee = initialized_block_env.basefee.to::<u64>();
    let block_number = initialized_block_env.number.to::<u64>();
    let beneficiary = initialized_block_env.coinbase;

    let system_caller = SystemCaller::default();

    // apply eip-4788 pre block contract call
    system_caller
        .pre_block_beacon_root_contract_call(&mut db, &initialized_cfg, &initialized_block_env, attributes.parent_beacon_block_root)
        .map_err(|err| {
            warn!(target: "payload_builder",
                parent_hash=%parent_header.hash(),
                %err,
                "failed to apply beacon root contract call for payload"
            );
            PayloadBuilderError::Internal(err.into())
        })?;

    // apply eip-2935 blockhashes update
    system_caller.pre_block_blockhashes_contract_call(
        &mut db,
        &initialized_cfg,
        &initialized_block_env,
        parent_header.hash(),
    )
    .map_err(|err| {
        warn!(target: "payload_builder", parent_hash=%parent_header.hash(), %err, "failed to update parent header blockhashes for payload");
        PayloadBuilderError::Internal(err.into())
    })?;

    // *** SIMULATION PHASE ***

    // Get inspector
    let inspector_lock = evm_config.with_inspector();
    let mut inspector = inspector_lock.write();
    
    // Get simulation transaction iterator
    let mut best_txs_simulation = best_txs(BestTransactionsAttributes::new(
        base_fee,
        initialized_block_env.get_blob_gasprice().map(|gasprice| gasprice as u64),
    ));
    
    // Create a temporary EVM for simulation
    // We'll simulate transaction execution to build the slot revert cache
    let evm_factory = evm_config.block_executor_factory().evm_factory();
    let mut sim_db = db.clone(); // Clone the database for simulation
    let sim_evm = evm_factory.create_evm_with_inspector(
        &mut sim_db,
        EvmEnv {
            cfg_env: initialized_cfg.clone(),
            block_env: initialized_block_env.clone(),
        },
        &mut *inspector
    );
    
    // Simulate transactions to surface reverts
    // Reverts are stored in the inspector's revert cache
    while let Some(pool_tx) = best_txs_simulation.next() {
        // convert tx to a signed transaction
        let tx = pool_tx.to_consensus();

        // Configure the environment for the tx
        let tx_env = evm_config.fill_tx_env(&mut TxEnv::default(), &tx.tx(), tx.signer());
        
        // Simulate the transaction - this is just to populate the revert cache
        // We don't need the actual result
        match sim_evm.transact(tx_env) {
            Ok(_) => {},
            Err(err) => {
                match err {
                    EVMError::Transaction(err) => {
                        if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                            // if the nonce is too low, we can skip this transaction
                            trace!(target: "payload_builder", %err, ?tx, "skipping nonce too low transaction");
                        } else {
                            // if the transaction is invalid, we can skip it
                            trace!(target: "payload_builder", %err, ?tx, "skipping invalid transaction");
                        }
                        continue;
                    }
                    err => {
                        // this is an error that we should treat as fatal for this attempt
                        return Err(PayloadBuilderError::Internal(err.into()));
                    }
                }
            }
        };
    }
    
    // Now apply the Bitcoin slot revert cache to the database
    // This is the critical masking step for Bitcoin transactions
    let revert_cache = inspector.slot_revert_cache.clone();
    
    // Apply mask to the database
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

            // Commit to account slot changes to state
            db.commit(changes);
        }
    }

    // Create execution context with properly masked database
    let execution_ctx = evm_config.context_for_next_block(
        &parent_header,
        (attributes.clone(), parent_header.clone()),
    );

    // Create the block executor with masked database
    let block_executor_factory = evm_config.block_executor_factory();
    let evm = evm_config.evm_factory().create_evm(&mut db, EvmEnv {
        cfg_env: initialized_cfg,
        block_env: initialized_block_env,
    });
    
    let mut executor = block_executor_factory.create_executor(evm, execution_ctx);

    // apply pre-execution changes
    executor.apply_pre_execution_changes()?;

    // Placeholder for transaction result
    let mut transactions = Vec::new();
    let mut receipts = Vec::new();
    let mut cumulative_gas_used = 0;
    
    // *** EXECUTION PHASE ***
    // TODO: Implement actual transaction execution
    // This would use the masked database to execute transactions properly
    
    // Create the final payload
    let payload = EthBuiltPayload::builder()
        .parent_hash(parent_header.hash())
        .block_number(block_number)
        .timestamp(attributes.timestamp())
        .prev_randao(attributes.prev_randao())
        .suggested_fee_recipient(beneficiary)
        .gas_limit(block_gas_limit)
        .withdrawals(attributes.withdrawals.clone())
        .parent_beacon_block_root(attributes.parent_beacon_block_root)
        .build();

    // Check if better than previous best
    if let Some(best) = best_payload {
        if !is_better_payload(best, &payload) {
            return Ok(BuildOutcome::NotBetterThanExisting);
        }
    }

    Ok(BuildOutcome::Better(payload))
}
