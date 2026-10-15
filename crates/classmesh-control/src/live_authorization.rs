//! Atomic, canonical enrolled control authorization snapshots.
//!
//! ONE trusted Service-owned publisher can atomically replace the full
//! AuthorizationStore without creating divergent credential/principal maps.
//! Readers take a brief std RwLock, clone a versioned immutable Arc snapshot,
//! then release the lock BEFORE any asynchronous IO. A cached snapshot is NOT
//! live authority: re-sample at every authorization point and after awaits.
//!
//! No network, Worker, or user-session policy publish endpoint is created here.
//! Production durable-policy reload/permission mutation is a SEPARATE gate.
//! This wrapper alone never authorizes sensitive clipboard payloads.
use std::sync::{Arc, RwLock};

use classmesh_security::AuthorizationStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveAuthorizationError {
    Poisoned,
    GenerationExhausted,
    /// The caller prepared an update from an older (or speculative future)
    /// policy. Never allow it to replace a newer in-process publication.
    StaleGeneration { expected: u64, current: u64 },
}

#[derive(Debug)]
struct PublishedAuthorization {
    generation: u64,
    authorization: Arc<AuthorizationStore>,
}

#[derive(Debug)]
pub struct LiveAuthorizationStore {
    published: RwLock<PublishedAuthorization>,
}

/// Version plus an immutable atomic snapshot. Do not retain this across an
/// unrelated awaited request; always acquire a new snapshot at each check.
#[derive(Debug, Clone)]
pub struct AuthorizationSnapshot {
    generation: u64,
    authorization: Arc<AuthorizationStore>,
}

impl AuthorizationSnapshot {
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn store(&self) -> &AuthorizationStore {
        self.authorization.as_ref()
    }

    #[must_use]
    pub fn arc(&self) -> Arc<AuthorizationStore> {
        Arc::clone(&self.authorization)
    }
}

impl LiveAuthorizationStore {
    #[must_use]
    pub fn new(initial: AuthorizationStore) -> Self {
        Self {
            published: RwLock::new(PublishedAuthorization {
                generation: 1,
                authorization: Arc::new(initial),
            }),
        }
    }

    /// Read the whole latest version and store atomically, never a mixture
    /// of credential and permission revisions. Poisoned lock denies access;
    /// it must not fall back to a potentially revoked policy.
    pub fn snapshot(&self) -> Result<AuthorizationSnapshot, LiveAuthorizationError> {
        let published = self
            .published
            .read()
            .map_err(|_| LiveAuthorizationError::Poisoned)?;
        Ok(AuthorizationSnapshot {
            generation: published.generation,
            authorization: Arc::clone(&published.authorization),
        })
    }

    /// Compare-and-publish from a trusted, previously observed version.
    /// Two asynchronous publishers with the same snapshot cannot both win:
    /// rejected stale writers leave policy AND generation untouched.
    ///
    /// This is an *in-process* concurrency fence, not persisted anti-rollback:
    /// a trusted durable reload still requires a separately protected,
    /// monotonic on-disk epoch and OS file ownership/reparse verification.
    pub fn publish_if_version(
        &self,
        expected: u64,
        next: AuthorizationStore,
    ) -> Result<u64, LiveAuthorizationError> {
        let mut published = self
            .published
            .write()
            .map_err(|_| LiveAuthorizationError::Poisoned)?;
        if published.generation != expected {
            return Err(LiveAuthorizationError::StaleGeneration {
                expected,
                current: published.generation,
            });
        }
        Self::replace(&mut published, next)
    }

    fn replace(
        published: &mut PublishedAuthorization,
        next: AuthorizationStore,
    ) -> Result<u64, LiveAuthorizationError> {
        let next_generation = published
            .generation
            .checked_add(1)
            .ok_or(LiveAuthorizationError::GenerationExhausted)?;
        *published = PublishedAuthorization {
            generation: next_generation,
            authorization: Arc::new(next),
        };
        Ok(next_generation)
    }

    /// TRUSTED LOCAL CALLER ONLY. Legacy unchecked in-process publication;
    /// asynchronous reloads MUST use publish_if_version to reject stale work.
    /// The caller validates the complete policy before invoking either path.
    pub fn publish(&self, next: AuthorizationStore) -> Result<u64, LiveAuthorizationError> {
        let mut published = self
            .published
            .write()
            .map_err(|_| LiveAuthorizationError::Poisoned)?;
        Self::replace(&mut published, next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_lock_never_falls_back_to_last_known_authorization() {
        let store = Arc::new(LiveAuthorizationStore::new(AuthorizationStore::default()));
        let corrupt = Arc::clone(&store);
        assert!(
            std::thread::spawn(move || {
                let _guard = corrupt.published.write().expect("initial lock");
                panic!("simulate publisher unwind while lock is held");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            store.snapshot(),
            Err(LiveAuthorizationError::Poisoned)
        ));
        assert_eq!(
            store.publish(AuthorizationStore::default()),
            Err(LiveAuthorizationError::Poisoned)
        );
    }

    #[test]
    fn exhausted_generation_cannot_replace_policy_or_wrap_to_a_previous_version() {
        let store = LiveAuthorizationStore::new(AuthorizationStore::default());
        {
            let mut guard = store.published.write().expect("test exclusive access");
            guard.generation = u64::MAX;
        }
        assert_eq!(
            store.publish(AuthorizationStore::default()),
            Err(LiveAuthorizationError::GenerationExhausted)
        );
        assert_eq!(store.snapshot().unwrap().version(), u64::MAX);
    }
}
