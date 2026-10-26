/// Bounded worker thread pool.
///
/// Replaces `thread::spawn` per query so an attacker can't exhaust process
/// memory by flooding us with concurrent queries. The pool has a fixed worker
/// count and a bounded queue; jobs that arrive while the queue is full are
/// rejected so the caller can drop them, the same as a full socket buffer would.
/// A job that panics is contained to that job and the worker keeps running.

use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    tx: mpsc::SyncSender<Job>,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ThreadPool {
    pub fn new(name: &str, workers: usize, queue_capacity: usize) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Job>(queue_capacity);
        let rx = Arc::new(Mutex::new(rx));
        let mut handles = Vec::with_capacity(workers);
        for id in 0..workers {
            let rx = Arc::clone(&rx);
            handles.push(thread::Builder::new()
                .name(format!("{}-worker-{}", name, id))
                .spawn(move || loop {
                    let job = {
                        let lock = rx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        lock.recv()
                    };
                    match job {
                        Ok(j) => {
                            if panic::catch_unwind(AssertUnwindSafe(j)).is_err() {
                                eprintln!("[threadpool] job panicked, worker continues");
                            }
                        }
                        Err(_) => break, // sender dropped, exit
                    }
                })
                .expect("spawn worker"));
        }
        Self { tx, _workers: handles }
    }

    /// Queue a job. Returns false when the queue is full and the job was dropped.
    pub fn submit<F: FnOnce() + Send + 'static>(&self, f: F) -> bool {
        self.tx.try_send(Box::new(f)).is_ok()
    }
}
