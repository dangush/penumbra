//! The Penumbra shielded pool [`Component`] and [`ActionHandler`] implementations.

mod action_handler;
mod assets;
mod fmd;
#[cfg(feature = "ibc")]
mod ics20_withdrawal_with_handler;
mod metrics;
mod note_manager;
mod shielded_pool;
#[cfg(feature = "ibc")]
mod transfer;

pub use self::metrics::register_metrics;
pub use assets::{AssetRegistry, AssetRegistryRead};
pub use fmd::ClueManager;
#[cfg(feature = "ibc")]
pub use ics20_withdrawal_with_handler::Ics20WithdrawalWithHandler;
pub use note_manager::NoteManager;
pub use shielded_pool::{ShieldedPool, StateReadExt, StateWriteExt};
#[cfg(feature = "ibc")]
pub use transfer::Ics20Transfer;

pub mod rpc;
