use bytes::Bytes;

use crate::{Enr, EnrKey, Key};

/// An Update operation over the [`Enr`].
pub enum Op {
    Insert { key: Key, content: Bytes },
    Remove { key: Key },
}

pub enum Error {
    ExceedsMaxSize,
}

pub struct Guard<'a, K: EnrKey> {
    enr: &'a mut Enr<K>,
    ops: &'a [Op],
}

impl<'a, K: EnrKey> Guard<'a, K> {
    pub fn noop(enr: &'a mut Enr<K>) -> Self {
        Guard { enr, ops: &[] }
    }

    pub fn with_ops(enr: &'a mut Enr<K>, ops: &'a [Op]) -> Self {
        Guard { enr, ops }
    }

    pub fn finish(self) -> Result<(), Error> {
        let Guard { enr, ops } = self;
        let current_size = enr.size();
        Ok(())
    }
}
