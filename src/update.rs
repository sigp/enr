//! Update operations over the [`Enr`].

use bytes::Bytes;

use crate::{error::Error, Enr, EnrKey, EnrPublicKey, NodeId, MAX_ENR_SIZE};

mod ops;

pub use ops::Update;
pub(crate) use ops::{UpdatesT, ValidUpdatesT};

/// An update guard over the [`Enr`].
/// The inverses are set as a generic to allow optimizing for single updates, multiple updates with
/// a known count of updates and arbitrary updates.
pub(crate) struct Guard<'a, K: EnrKey, Up: UpdatesT> {
    /// Testing keep a clone of the enr to verify it remains unchanged on failure.
    #[cfg(test)]
    enr_backup: Enr<K>,
    /// [`Enr`] with update [`Op`]s already applied.
    enr: &'a mut Enr<K>,
    /// Inverses that would need to be applied to the [`Enr`] to restore [`Enr::content`].
    ///
    /// Inverses must be in the order in which they were obtained, so that applying them in
    /// reserved order produces the original content.
    inverses: Up::ValidatedUpdates,
}

impl<'a, K: EnrKey, Up: UpdatesT> Guard<'a, K, Up> {
    /// Create a new guard verifying the update and applying it to the the [`Enr`].
    ///
    /// If validation fails, an error is returned and it's guaranteed that the [`Enr`] has not been
    /// changed.
    pub fn new(enr: &'a mut Enr<K>, updates: Up) -> Result<Self, Error> {
        // validate the update
        let updates = updates.to_valid()?;
        #[cfg(test)]
        let enr_backup = Enr {
            seq: enr.seq,
            node_id: enr.node_id.clone(),
            content: enr.content.clone(),
            signature: enr.signature.clone(),
            phantom: std::marker::PhantomData,
        };
        // apply the valid operation to the enr and create the inverse
        let inverses = updates.apply_and_invert(enr);
        Ok(Self {
            #[cfg(test)]
            enr_backup,
            enr,
            inverses,
        })
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
    ) -> Result<<Up::ValidatedUpdates as ValidUpdatesT>::Output, Error> {
        let Guard {
            #[cfg(test)]
            enr_backup,
            enr,
            inverses,
        } = self;
        let mut revert = RevertOps::new(inverses);

        // 1. set the public key
        let public_key = signing_key.public();
        let encoded_pk = rlp::encode(&public_key.encode().as_ref()).freeze();
        let pk_name = public_key.enr_key();
        let prev_pk_contents = enr.content.insert(public_key.enr_key(), encoded_pk);
        revert.public_key = Some((pk_name, prev_pk_contents));

        // 2. set the new sequence number
        let Some(new_seq) = enr.seq.checked_add(1) else {
            revert.recover(enr);
            #[cfg(test)]
            assert_eq!(&enr_backup, enr);
            return Err(Error::SequenceNumberTooHigh);
        };
        revert.seq = Some(std::mem::replace(&mut enr.seq, new_seq));

        // 3. sign the ENR
        revert.signature = match enr.compute_signature(signing_key) {
            Ok(signature) => Some(std::mem::replace(&mut enr.signature, signature)),
            Err(error) => {
                revert.recover(enr);
                #[cfg(test)]
                assert_eq!(&enr_backup, enr);
                return Err(error);
            }
        };

        // 4. check the encoded size
        if enr.size() > MAX_ENR_SIZE {
            revert.recover(enr);
            #[cfg(test)]
            assert_eq!(&enr_backup, enr);
            return Err(Error::ExceedsMaxSize);
        }

        // 5. update the node_id
        enr.node_id = NodeId::from(public_key);

        // nothing to revert, return the content inverses since those identify what was done
        let RevertOps {
            content_inverses, ..
        } = revert;
        Ok(content_inverses.inverse_to_output())
    }
}

/// Keeps track of previous values that need to be applied to the [`Enr`] to restore it.
pub struct RevertOps<I> {
    content_inverses: I,
    public_key: Option<(Vec<u8>, Option<Bytes>)>,
    seq: Option<u64>,
    signature: Option<Vec<u8>>,
}

impl<I> RevertOps<I> {
    fn new(content_inverses: I) -> Self {
        RevertOps {
            content_inverses,
            seq: None,
            signature: None,
            public_key: None,
        }
    }
}

impl<I: ValidUpdatesT> RevertOps<I> {
    pub fn recover<K: EnrKey>(self, enr: &mut Enr<K>) {
        let RevertOps {
            content_inverses,
            public_key,
            seq,
            signature,
        } = self;

        // first do the content, since it could have included the contents of the public key as an
        // explicit update
        content_inverses.apply_as_inverse(enr);
        if let Some(seq) = seq {
            enr.seq = seq;
        }

        if let Some(signature) = signature {
            enr.signature = signature;
        }

        if let Some((pk_name, pk_prev_contents)) = public_key {
            match pk_prev_contents {
                Some(content) => enr.content.insert(pk_name, content),
                None => enr.content.remove(&pk_name),
            };
        }
    }
}
