//! The one thread that starts and reaps cw-egress's children.
//!
//! A child is killed when the thread that forked it exits, not when its
//! process does (`codewire_confinement::spawn::prepare_isolated_child`). A
//! runtime's threads come and go, so no child is ever forked from one: every
//! start goes through this thread, which lives until the launcher and every
//! process it started are gone. It reaps them too, so a blocking wait never
//! runs on a runtime thread.

use std::io;
use std::process::Child;
use std::sync::mpsc;

use codewire_confinement::spawn::ImageCommand;
use tokio::sync::oneshot;

use super::StartError;

enum Job {
    Start(ImageCommand, oneshot::Sender<io::Result<Child>>),
    /// A killed child to wait for. The sender, when there is one, hears that
    /// it is reaped.
    Reap(Child, Option<oneshot::Sender<()>>),
}

#[derive(Clone, Debug)]
pub(super) struct Spawner {
    jobs: mpsc::Sender<Job>,
}

impl Spawner {
    pub(super) fn start() -> io::Result<Self> {
        let (jobs, queue) = mpsc::channel();
        std::thread::Builder::new()
            .name("cw-egress-spawn".to_owned())
            .spawn(move || {
                for job in queue {
                    match job {
                        Job::Start(command, started) => {
                            // The asker may have given up waiting. Its child
                            // then has no owner, so it ends here.
                            if let Err(Ok(mut orphan)) = started.send(command.spawn()) {
                                reap(&mut orphan);
                            }
                        }
                        Job::Reap(mut child, reaped) => {
                            reap(&mut child);
                            if let Some(reaped) = reaped {
                                // Nobody waiting is fine: the child is reaped.
                                let _ = reaped.send(());
                            }
                        }
                    }
                }
            })?;
        Ok(Self { jobs })
    }

    /// Starts `command`'s child on the spawning thread.
    pub(super) async fn spawn(&self, command: ImageCommand) -> Result<Process, StartError> {
        let (started, child) = oneshot::channel();
        self.jobs
            .send(Job::Start(command, started))
            .map_err(|_| StartError::Spawn)?;
        let child = child
            .await
            .map_err(|_| StartError::Spawn)?
            .map_err(|_| StartError::Spawn)?;
        Ok(Process {
            child: Some(child),
            spawner: self.clone(),
        })
    }
}

/// Kills `child` and waits for it.
fn reap(child: &mut Child) {
    // Killing a child that already exited is not a failure, and a wait can
    // only fail for a child that is already reaped.
    let _ = child.kill();
    let _ = child.wait();
}

/// One running child. Dropping it kills it, and the spawning thread reaps it.
#[derive(Debug)]
pub(super) struct Process {
    child: Option<Child>,
    spawner: Spawner,
}

impl Process {
    pub(super) fn id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Kills the process and returns once it is reaped.
    pub(super) async fn end(mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // Killed here, before anything else can happen; the wait, which can
        // block, is the spawning thread's.
        let _ = child.kill();
        let (reaped, done) = oneshot::channel();
        if self
            .spawner
            .jobs
            .send(Job::Reap(child, Some(reaped)))
            .is_ok()
        {
            // An error means the spawning thread is gone, and its children
            // with it.
            let _ = done.await;
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Killed here, so the process is gone whatever happens to the
            // queue; reaped on the spawning thread.
            let _ = child.kill();
            // An error means the spawning thread is gone, and its children
            // with it.
            let _ = self.spawner.jobs.send(Job::Reap(child, None));
        }
    }
}
