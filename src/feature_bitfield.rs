/// The kind of feature that can be supported.
pub type Feature = u8;

// Current Feature Map:
// 1 - NAT - Is Nat supported

/// Represents the decimal notation of the bitfield location for the feature.
pub const NAT_FEATURE: Feature = 1;

/// Discv5 Capable Features.
///
/// This is a bitfield that is stored inside ENRs to indicate which features of Discv5 are
/// supported.
/// Currently the only optional feature is NAT support. This consumes the first bit location.
/// We currently store a single u8, which is fine as RLP encoding strips the leading 0s.
#[derive(Clone, Debug, Default)]
pub struct FeatureBitfield {
    bitfield: u8, // Supports up to 256 unique features
}

impl FeatureBitfield {
    /// Create a new instance of [`FeatureBitfield`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bitfield to indicate support for the NAT feature.
    pub fn set_nat(&mut self) {
        self.bitfield |= NAT_FEATURE;
    }

    /// Returns true if the NAT feature is set.
    #[must_use]
    pub const fn nat(&self) -> bool {
        self.bitfield & NAT_FEATURE == NAT_FEATURE
    }

    /// Enables one or many features.
    pub fn set_features(&mut self, features: Feature) {
        self.bitfield |= features;
    }

    /// Returns if the feature is supported.
    #[must_use]
    pub const fn supports_feature(&self, feature: Feature) -> bool {
        self.bitfield & feature == feature
    }

    /// Returns the decimal representation of the features supported.
    #[must_use]
    pub const fn features(&self) -> Feature {
        self.bitfield
    }
}

impl From<&[u8]> for FeatureBitfield {
    fn from(src: &[u8]) -> Self {
        Self {
            bitfield: *src.first().unwrap_or(&0),
        }
    }
}
