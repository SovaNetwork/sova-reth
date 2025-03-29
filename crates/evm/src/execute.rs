use std::sync::Arc;

use alloy_primitives::map::foldhash::{HashMap, HashMapExt};
use alloy_evm::{
    self,
    eth::EthBlockExecutor,
};

use reth::builder::{components::ExecutorBuilder, BuilderContext};
use reth_chainspec::ChainSpec;

use reth_evm::{
    execute::{
        BlockExecutionError, BlockExecutor, InternalBlockExecutionError
    }, ConfigureEvm, Database, Evm, OnStateHook
};
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_ethereum::BasicBlockExecutorProvider;
use reth_primitives::{EthPrimitives, Receipt, Account};
use reth_provider::BlockExecutionResult;
use reth_revm::{
    context::{result::ExecutionResult, TxEnv},
    db::State,
    DatabaseCommit,
};
use reth_evm_ethereum::RethReceiptBuilder;

use crate::{inspector::WithInspector, MyEvmConfig, MyEvmFactory};

/// A custom executor implementation that uses our Sova-specific components
pub struct MyBlockExecutor<'a, Evm> {
    /// Inner Ethereum execution strategy.
    inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec>, &'a RethReceiptBuilder>,
    /// Reference to the ChainSpec
    chain_spec: &'a Arc<ChainSpec>,
    /// Reference to our EVM config with Bitcoin precompile
    evm_config: &'a MyEvmConfig,
}

impl<'a, Evm> MyBlockExecutor<'a, Evm> {
    /// Creates a new MyBlockExecutor instance
    pub fn new(
        evm: Evm,
        ctx: reth_evm::eth::EthBlockExecutionCtx<'a>,
        chain_spec: &'a Arc<ChainSpec>,
        receipt_builder: &'a reth_evm_ethereum::RethReceiptBuilder,
        evm_config: &'a MyEvmConfig,
    ) -> Self {
        Self {
            inner: EthBlockExecutor::new(evm, ctx, chain_spec, receipt_builder),
            chain_spec,
            evm_config,
        }
    }
}

impl<'db, DB, E> BlockExecutor for MyBlockExecutor<'_, E>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = TxEnv>,
{
    type Transaction = reth_primitives::TransactionSigned;
    type Receipt = Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: reth_primitives::Recovered<&reth_primitives::TransactionSigned>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        // Execute the transaction using the inner executor
        let result = self.inner.execute_transaction_with_result_closure(tx, f)?;
        
        // In v1.1.5, there was custom logic after each transaction execution
        // We could add that here if needed
        
        Ok(result)
    }

    fn finish(mut self) -> Result<(Self::Evm, BlockExecutionResult<Receipt>), BlockExecutionError> {
        // Get the inspector lock before finishing
        let inspector_lock = self.evm_config.with_inspector();
        let mut inspector = inspector_lock.write();

        // First get the result from the inner executor
        let (evm, output) = self.inner.finish()?;
        
        // Update sentinel locks for Bitcoin transactions
        // This was done in the original apply_post_execution_changes
        let block_num: u64 = evm.block().number + 1; // Lock for next block
        inspector.update_sentinel_locks(block_num)
            .map_err(|err| {
                BlockExecutionError::Internal(InternalBlockExecutionError::msg(format!(
                    "Execution error: Failed to update sentinel locks: {}",
                    err
                )))
            })?;

        Ok((evm, output))
    }

    // Use a type alias to avoid trait being private
    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
}

/// Factory for creating custom executors
#[derive(Clone)]
pub struct MyExecutionStrategyFactory {
    /// Config for EVM that includes Bitcoin precompile setup
    pub evm_config: MyEvmConfig,
    /// The chain spec
    pub chain_spec: Arc<ChainSpec>,
}

impl MyExecutionStrategyFactory {
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: MyEvmConfig) -> Self {
        Self { chain_spec, evm_config }
    }
    
    pub fn create_executor<'a, DB, I>(
        &'a self,
        evm: <MyEvmFactory as alloy_evm::EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: <reth_evm_ethereum::EthEvmConfig<MyEvmFactory> as alloy_evm::block::BlockExecutorFactory>::ExecutionCtx<'a>,
    ) -> MyBlockExecutor<'a, <MyEvmFactory as alloy_evm::EvmFactory>::Evm<&'a mut State<DB>, I>>
    where
        DB: Database + 'a,
        I: reth_revm::inspector::Inspector<reth_revm::context_interface::ContextTr, reth_revm::interpreter::interpreter::EthInterpreter> + 'a,
    {
        // Get the inspector to check if we need to mask storage
        let inspector_lock = self.evm_config.with_inspector();
        let inspector = inspector_lock.read();
        
        // Apply Bitcoin slot revert cache to mask storage slots
        // This is similar to what was in the original execute_transactions method
        if !inspector.slot_revert_cache.is_empty() {
            let db = evm.db_mut();
            
            // Apply mask to the database like we did in the payload builder
            for (address, transition) in &inspector.slot_revert_cache {
                for (slot, slot_data) in &transition.storage {
                    let prev_value = slot_data.previous_or_original_value;
                    
                    // Load account from state
                    if let Ok(acc) = db.load_cache_account(*address) {
                        // Set slot in account to previous value
                        if let Some(a) = acc.account.as_mut() {
                            a.storage.insert(*slot, prev_value);
                        }
                        
                        // Convert to account info, mark as modified and commit
                        if let Some(account_info) = acc.account_info() {
                            // Create a HashMap to store the change
                            let mut changes = HashMap::new();
                            changes.insert(*address, Account::from(account_info));
                            
                            // Commit account slot changes to state
                            db.commit(changes);
                        }
                    }
                }
            }
        }
        
        // Use the inner factory to create the base executor with masked database
        let inner = self.evm_config.block_executor_factory().create_executor(evm, ctx);
        
        // Wrap with our custom executor
        MyBlockExecutor { 
            inner,
            chain_spec: &self.chain_spec,
            evm_config: &self.evm_config,
        }
    }
}

/// A custom executor builder that creates our custom BlockExecutor
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = MyEvmConfig;
    type Executor = BasicBlockExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        // Create our EVM config
        let evm_config = ctx.config.sova_config.as_ref().map(|config| {
            MyEvmConfig::new(
                config,
                ctx.chain_spec(),
                ctx.config.bitcoin_client.clone(),
                ctx.task_executor().clone(),
            )
        }).ok_or_else(|| eyre::eyre!("Missing Sova configuration"))??;
        
        // Create our executor factory with the chain spec
        let executor_factory = MyExecutionStrategyFactory::new(
            ctx.chain_spec(),
            evm_config.clone()
        );
        
        // Wrap in the provider
        let executor = reth_evm::execute::BasicBlockExecutorProvider::new(executor_factory);
        
        Ok((evm_config, executor))
    }
}
