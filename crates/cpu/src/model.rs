//! Explicit guest CPU compatibility profiles and their implemented features.

const EFLAGS_ID: u32 = 1 << 21;
const CPUID_EDX_FPU: u32 = 1 << 0;
const CPUID_EDX_CX8: u32 = 1 << 8;
const CPUID_EDX_CMOV: u32 = 1 << 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CpuModel {
    /// The documented i486 plus x87 baseline. CPUID and later extensions are absent.
    I486,
    /// Adds the routed `CMPXCHG8B` instruction and CPUID to the baseline.
    /// This is a compatibility profile, not a complete Pentium implementation.
    PentiumCompat,
    /// Adds routed integer and x87 conditional moves to `PentiumCompat`.
    /// This is a compatibility profile, not a complete Pentium Pro implementation.
    PentiumProCompat,
}

impl CpuModel {
    /// The architectural family level exposed by this compatibility profile.
    pub const fn architecture_family(self) -> u8 {
        match self {
            Self::I486 => 4,
            Self::PentiumCompat => 5,
            Self::PentiumProCompat => 6,
        }
    }

    /// Whether CPUID is present and EFLAGS.ID can be changed by 32-bit flag images.
    pub const fn has_cpuid(self) -> bool {
        !matches!(self, Self::I486)
    }

    /// Whether the selected profile includes the interpreter's x87 execution path.
    pub const fn supports_x87(self) -> bool {
        true
    }

    /// Whether the selected profile enables its routed CMPXCHG8B path.
    pub const fn supports_cmpxchg8b(self) -> bool {
        matches!(self, Self::PentiumCompat | Self::PentiumProCompat)
    }

    /// Whether the selected profile enables its routed CMOVcc paths.
    pub const fn supports_cmov(self) -> bool {
        matches!(self, Self::PentiumProCompat)
    }

    pub(crate) const fn supports_instruction_features(
        self,
        required: CpuFeatureSet,
    ) -> bool {
        required.0 & !self.available_features().0 == 0
    }

    pub(crate) const fn normalize_eflags(self, eflags: u32) -> u32 {
        if self.has_cpuid() {
            eflags
        } else {
            eflags & !EFLAGS_ID
        }
    }

    pub(crate) const fn cpuid_result(self, leaf: u32) -> [u32; 4] {
        if !self.has_cpuid() {
            return [0; 4];
        }

        match leaf {
            0 => [
                1,
                u32::from_le_bytes(*b"Gene"),
                u32::from_le_bytes(*b"IA32"),
                u32::from_le_bytes(*b"ric "),
            ],
            1 => [
                (self.architecture_family() as u32) << 8,
                0,
                0,
                self.cpuid_feature_edx(),
            ],
            _ => [0; 4],
        }
    }

    const fn available_features(self) -> CpuFeatureSet {
        let mut features = CpuFeatureSet::EMPTY;
        if self.supports_x87() {
            features = features.union(CpuFeatureSet::FPU);
        }
        if self.has_cpuid() {
            features = features.union(CpuFeatureSet::CPUID);
        }
        if self.supports_cmpxchg8b() {
            features = features.union(CpuFeatureSet::CX8);
        }
        if self.supports_cmov() {
            features = features.union(CpuFeatureSet::CMOV);
        }
        if matches!(self, Self::I486) {
            // Intel486 retains the legacy test-register MOV encodings. Their
            // effect is still a typed backend gap after architectural checks.
            features = features.union(CpuFeatureSet::TEST_REGISTERS);
        }
        features
    }

    const fn cpuid_feature_edx(self) -> u32 {
        let features = self.available_features();
        let mut result = 0;
        if features.contains(CpuFeatureSet::FPU) {
            result |= CPUID_EDX_FPU;
        }
        if features.contains(CpuFeatureSet::CX8) {
            result |= CPUID_EDX_CX8;
        }
        if features.contains(CpuFeatureSet::CMOV) {
            result |= CPUID_EDX_CMOV;
        }
        result
    }
}

impl Default for CpuModel {
    fn default() -> Self {
        // Keep the previously unconditional CMPXCHG8B/CMOV execution paths
        // available until the machine owner selects a stricter profile.
        Self::PentiumProCompat
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuFeatureSet(u16);

impl CpuFeatureSet {
    pub(crate) const EMPTY: Self = Self(0);
    pub(crate) const FPU: Self = Self(1 << 0);
    pub(crate) const CPUID: Self = Self(1 << 1);
    pub(crate) const CX8: Self = Self(1 << 2);
    pub(crate) const CMOV: Self = Self(1 << 3);
    pub(crate) const SSE3: Self = Self(1 << 4);
    pub(crate) const TEST_REGISTERS: Self = Self(1 << 5);
    pub(crate) const UNMODELED: Self = Self(1 << 15);

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
