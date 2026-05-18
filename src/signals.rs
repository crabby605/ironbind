/// Signal Handler — SIGHUP for zone reloading
///
/// Provides robust SIGHUP signal handling for hot zone reloading
/// Uses atomic flags to communicate between signal handler and main loop

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag set by SIGHUP handler
pub static RELOAD_SIGNAL: AtomicBool = AtomicBool::new(false);

/// Check if reload signal was received
pub fn should_reload() -> bool {
    RELOAD_SIGNAL.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

/// Signal handler for SIGHUP
#[cfg(unix)]
pub fn setup_signal_handler() {
    extern "C" fn handle_sighup(_: i32) {
        RELOAD_SIGNAL.store(true, Ordering::SeqCst);
    }

    #[cfg(unix)]
    {
        unsafe {
            use std::os::raw::c_int;
            extern "C" {
                fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> extern "C" fn(c_int);
            }
            const SIGHUP: c_int = 1;
            let _ = signal(SIGHUP, handle_sighup);
        }
    }

    eprintln!("[signals] SIGHUP handler installed for zone reloading");
}

#[cfg(not(unix))]
pub fn setup_signal_handler() {
    eprintln!("[signals] Signal handling not available on this platform");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reload_flag() {
        assert!(!should_reload());
        RELOAD_SIGNAL.store(true, Ordering::SeqCst);
        assert!(should_reload());
    }
}

