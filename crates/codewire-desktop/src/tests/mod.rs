mod context_menu_tests;
mod native_ui_tests;
mod pane_tests;
mod terminal_tests;

/// Own real local PTYs until their fixture's background workers have reaped them.
pub(crate) type PtyFixtureChild =
    std::sync::Arc<std::sync::Mutex<Box<dyn portable_pty::Child + Send + Sync>>>;

struct PtyFixture {
    input: std::sync::mpsc::Sender<crate::terminal::backend::PtyInput>,
    child: std::sync::mpsc::Receiver<PtyFixtureChild>,
    worker: std::thread::JoinHandle<()>,
}

#[derive(Default)]
pub(crate) struct PtyFixtures {
    workers: Vec<PtyFixture>,
}

impl PtyFixtures {
    pub(crate) fn push(
        &mut self,
        input: std::sync::mpsc::Sender<crate::terminal::backend::PtyInput>,
        child: std::sync::mpsc::Receiver<PtyFixtureChild>,
        worker: std::thread::JoinHandle<()>,
    ) {
        self.workers.push(PtyFixture {
            input,
            child,
            worker,
        });
    }
}

impl Drop for PtyFixtures {
    fn drop(&mut self) {
        use crate::terminal::backend::PtyInput;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(30);
        let mut failures = Vec::new();
        for fixture in &self.workers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(child) = fixture.child.recv_timeout(remaining) else {
                failures.push("local PTY fixture did not supply its child");
                continue;
            };
            let mut next_exit = Instant::now();
            loop {
                if Instant::now() >= deadline {
                    failures.push("local PTY fixture child did not exit within 30 seconds");
                    break;
                }
                // Startup can change the terminal input mode. Keep the
                // transport open and request a normal shell exit after that
                // transition, so the shell can reap its own startup children.
                if Instant::now() >= next_exit {
                    let _ = fixture.input.send(PtyInput::Data(b"exit\n".to_vec()));
                    next_exit = Instant::now() + Duration::from_millis(50);
                }
                match child.try_lock() {
                    Ok(mut child) => match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                        Err(_) => {
                            failures.push("local PTY fixture child status failed");
                            break;
                        }
                    },
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        failures.push("local PTY fixture child owner panicked");
                        break;
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {}
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        for fixture in &self.workers {
            let _ = fixture.input.send(PtyInput::Shutdown);
        }
        for fixture in self.workers.drain(..) {
            let worker = fixture.worker;
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !worker.is_finished() {
                failures.push("local PTY fixture worker did not finish within 30 seconds");
            } else if worker.join().is_err() {
                failures.push("local PTY fixture worker panicked");
            }
        }

        if !std::thread::panicking() {
            assert!(failures.is_empty(), "{}", failures.join("; "));
        }
    }
}
