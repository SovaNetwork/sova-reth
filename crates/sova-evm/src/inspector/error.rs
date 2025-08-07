#[derive(Debug)]
pub enum SlotProviderError {
    BitcoinNodeUnavailable(String),
    ServiceUnavailable(String),
    InvalidRequest(String),
    Timeout(String),
    UnknownSlotStatus {
        contract_address: String,
        slot_index: Vec<u8>,
        message: String,
    },
    Transport(String),
}

impl std::fmt::Display for SlotProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotProviderError::BitcoinNodeUnavailable(msg) => write!(f, "Bitcoin node unavailable: {msg}"),
            SlotProviderError::ServiceUnavailable(msg) => write!(f, "Service unavailable: {msg}"),
            SlotProviderError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            SlotProviderError::Timeout(msg) => write!(f, "Timeout: {msg}"),
            SlotProviderError::UnknownSlotStatus { contract_address, slot_index, message } => {
                write!(f, "Unknown slot status for {}:{}: {}", contract_address, hex::encode(slot_index), message)
            },
            SlotProviderError::Transport(msg) => write!(f, "Transport error: {msg}"),
        }
    }
}

impl std::error::Error for SlotProviderError {}