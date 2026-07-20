use std::sync::atomic::{AtomicU64, Ordering};

static BYTES_DONE: AtomicU64 = AtomicU64::new(0);
static BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn reset(total: u64) {
    BYTES_TOTAL.store(total, Ordering::Relaxed);
    BYTES_DONE.store(0, Ordering::Relaxed);
}

pub fn advance(bytes: u64) {
    BYTES_DONE.fetch_add(bytes, Ordering::Relaxed);
}

/// Set the absolute done count — used on the sender, which tracks progress
/// from the receiver's confirmed-bytes reports rather than local writes.
pub fn set_done(bytes: u64) {
    BYTES_DONE.store(bytes, Ordering::Relaxed);
}

pub fn retract(bytes: u64) {
    BYTES_DONE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(bytes))
    }).ok();
}

pub fn get() -> (u64, u64) {
    let done = BYTES_DONE.load(Ordering::Relaxed);
    let total = BYTES_TOTAL.load(Ordering::Relaxed);
    (done, total)
}
