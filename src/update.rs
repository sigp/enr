//! Update operations over the [`Enr`].

use bytes::Bytes;

use crate::{error::Error, Enr, EnrKey, EnrPublicKey, NodeId, MAX_ENR_SIZE};

mod ops;

pub use ops::Update;
use ops::{UpdatesT, ValidUpdatesT};

/// An update guard over the [`Enr`].
/// The inverses are set as a generic to allow optimizing for single updates, multiple updates with
/// a known count of updates and arbitrary updates.
pub(crate) struct Guard<'a, K: EnrKey, Up: UpdatesT> {
    /// [`Enr`] with update [`Op`]s already applied.
    enr: &'a mut Enr<K>,
    /// Inverses that would need to be applied to the [`Enr`] to restore [`Enr::content`].
    ///
    /// Inverses must be in the order in which they were obtained, so that applying them in
    /// reserved order produces the original content.
    inverses: Up::ValidatedUpdates,
}

/// Implementation for a single update
impl<'a, K: EnrKey, Up: UpdatesT> Guard<'a, K, Up> {
    /// Create a new guard verifying the update and applying it to the the [`Enr`].
    /// If validation fails, it's guaranteed that the [`Enr`] has not been changed with
    /// an error returned.
    // NOTE: this is expanded to n-tuples via macros
    pub fn new(enr: &'a mut Enr<K>, updates: Up) -> Result<Self, Error> {
        // validate the update
        let updates = updates.to_valid()?;
        // apply the valid operation to the enr and create the inverse
        let inverses = updates.apply_and_invert(enr);
        Ok(Self { enr, inverses })
    }

    /// Applies the remaining operations in a valid [`Enr`] update:
    ///
    /// 1. Add the public key matching the signing key to the contents.
    /// 2. Update the sequence number.
    /// 3. Sign the [`Enr`].
    /// 4. Verify that the encoded [`Enr`] is within spec lengths.
    /// 5. Update the cache'd node id
    ///
    /// If any of these steps fails, a [`Revert`] object is returned that allows to reset the
    /// [`Enr`] and obtain the error that occurred.
    pub fn finish(
        self,
        signing_key: &K,
    ) -> Result<Up::ValidatedUpdates, Revert<'a, K, Up::ValidatedUpdates>> {
        let Guard { enr, inverses } = self;
        let mut revert = RevertOps::new(inverses);

        // 1. set the public key
        let public_key = signing_key.public();
        revert.key = enr.content.insert(
            public_key.enr_key(),
            rlp::encode(&public_key.encode().as_ref()).freeze(),
        );

        // 2. set the new sequence number
        revert.seq = Some(enr.seq());
        enr.seq = match enr.seq.checked_add(1) {
            Some(seq) => seq,
            None => {
                return Err(Revert {
                    enr,
                    pending: revert,
                    error: Error::SequenceNumberTooHigh,
                })
            }
        };

        // 3. sign the ENR
        revert.signature = Some(enr.signature.clone());
        enr.signature = match enr.compute_signature(signing_key) {
            Ok(signature) => signature,
            Err(_) => {
                return Err(Revert {
                    enr,
                    pending: revert,
                    error: Error::SigningError,
                })
            }
        };

        // the size of the node id is fixed, and its encoded size depends exclusively on the data
        // size, so we first check the size and then update the node id. This allows us to not need
        // to track the previous node id in case of failure since this is the last step

        // 4. check the encoded size
        if enr.size() > MAX_ENR_SIZE {
            return Err(Revert {
                enr,
                pending: revert,
                error: Error::ExceedsMaxSize,
            });
        }

        // 5. update the node_id
        enr.node_id = NodeId::from(public_key);

        // nothing to revert, return the content inverses since those identify what was done
        let RevertOps {
            content_inverses, ..
        } = revert;
        Ok(content_inverses)
    }
}

/// Helper struct that handles recovering the modified [`Enr`] to it's original state.
pub(crate) struct Revert<'a, K: EnrKey, I: ValidUpdatesT> {
    /// Dirt [`Enr`] to recover.
    enr: &'a mut Enr<K>,
    /// Operations to apply to the [`Enr`] to restore to it's original state.
    pending: RevertOps<I>,
    /// Error that occurred in [`Guard::finish`]
    error: Error,
}

/// Keeps track of operations that need to be applied to the [`Enr`] to restore it.
pub struct RevertOps<I> {
    content_inverses: I,
    key: Option<Bytes>,
    seq: Option<u64>,
    signature: Option<Vec<u8>>,
}

impl<I> RevertOps<I> {
    fn new(content_inverses: I) -> Self {
        RevertOps {
            content_inverses,
            key: None,
            seq: None,
            signature: None,
        }
    }
}

impl<'a, K: EnrKey, I: ValidUpdatesT> Revert<'a, K, I> {
    fn recover(self) -> Error {
        let Revert {
            enr,
            pending:
                RevertOps {
                    content_inverses,
                    key,
                    seq,
                    signature,
                },
            error,
        } = self;

        error
    }
}
