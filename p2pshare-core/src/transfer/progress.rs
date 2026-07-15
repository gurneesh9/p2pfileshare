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

pub fn get() -> (u64, u64) {
    let done = BYTES_DONE.load(Ordering::Relaxed);
    let total = BYTES_TOTAL.load(Ordering::Relaxed);
    (done, total)
}
