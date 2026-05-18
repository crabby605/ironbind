/// Bounded worker thread pool.
///
/// Replaces `thread::spawn` per query so an attacker can't exhaust process
/// memory by flooding us with concurrent queries. The pool has a fixed worker
/// count and an unbounded MPSC queue; jobs that arrive when all workers are
/// busy queue up rather than spawning new OS threads.

use std::sync::{Arc, Mutex, mpsc};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    tx: mpsc::Sender<Job>,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ThreadPool {
    pub fn new(workers: usize) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let mut handles = Vec::with_capacity(workers);
        for id in 0..workers {
            let rx = Arc::clone(&rx);
            handles.push(thread::Builder::new()
                .name(format!("dns-worker-{}", id))
                .spawn(move || loop {
                    let job = {
                        let lock = rx.lock().unwrap();
                        lock.recv()
                    };
                    match job {
                        Ok(j) => j(),
                        Err(_) => break, // sender dropped, exit
                    }
                })
                .expect("spawn worker"));
        }
        Self { tx, _workers: handles }
    }

    pub fn submit<F: FnOnce() + Send + 'static>(&self, f: F) {
        if let Err(e) = self.tx.send(Box::new(f)) {
            eprintln!("[threadpool] submit failed: {}", e);
        }
    }
}
