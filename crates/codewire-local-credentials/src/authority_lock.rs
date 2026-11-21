//! The authority's exclusive lock on its root, so one authority serves it.

use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};

use crate::LocalCredentialError;
#[cfg(unix)]
use crate::validate_private_file;

#[cfg(unix)]
const AUTHORITY_LOCK_FILE: &str = "authority.lock";

pub(crate) struct AuthorityLock {
    #[cfg(unix)]
    pub(crate) _file: fs::File,
}

impl AuthorityLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self, LocalCredentialError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(LocalCredentialError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let path = root.join(AUTHORITY_LOCK_FILE);
            let descriptor = open(
                &path,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
            let file = fs::File::from(descriptor);
            validate_private_file(
                &file
                    .metadata()
                    .map_err(|_| LocalCredentialError::InvalidDatabasePath)?,
            )?;
            // CLOEXEC still permits a concurrent fork to retain this lock
            // briefly until exec. Match the supervisor's bounded handoff;
            // never unlock or take ownership from a live authority.
            const RETRY_DELAY: Duration = Duration::from_millis(10);
            const MAX_RETRIES: usize = 25;
            let mut retries = 0;
            loop {
                match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => return Ok(Self { _file: file }),
                    Err(error) if error == rustix::io::Errno::INTR && retries < MAX_RETRIES => {
                        retries += 1;
                    }
                    Err(error)
                        if error == rustix::io::Errno::WOULDBLOCK && retries < MAX_RETRIES =>
                    {
                        retries += 1;
                        std::thread::sleep(RETRY_DELAY);
                    }
                    Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                        return Err(LocalCredentialError::AlreadyRunning);
                    }
                    Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
                }
            }
        }
    }
}
