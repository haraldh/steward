// SPDX-License-Identifier: Apache-2.0

//! Attributes (Section 38.7.1)
//! The attributes of an enclave are specified by the struct below as described.

#[cfg(test)]
use crate::testaso;
use flagset::{flags, FlagSet};
#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

flags! {
    /// Section 38.7.1.
    #[derive(Ord, PartialOrd)]
    #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
    #[allow(non_camel_case_types)]
    pub enum Flags: u64 {
        /// Enclave has been initialized by EINIT.
        INIT = 1 << 0,
        /// Perm for debugger to r/w enclave data with EDBGRD and EDBGWR.
        DEBUG = 1 << 1,
        /// Enclave runs in 64-bit mode.
        BIT64 = 1 << 2,
        /// Provisioning Key is available from EGETKEY.
        PROV_KEY = 1 << 4,
        /// EINIT token key is available from EGETKEY.
        EINIT_KEY = 1 << 5,
        /// Enable CET attributes.
        CET = 1 << 6,
        /// Key Separation and Sharing enabled.
        KSS = 1 << 7
    }
}

impl Default for Flags {
    fn default() -> Self {
        Self::BIT64
    }
}

flags! {
    /// Section 42.7.2.1; more info can be found at https://en.wikipedia.org/wiki/Control_register.
    #[derive(Ord, PartialOrd)]
    #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
    #[allow(non_camel_case_types)]
    pub enum Xfrm: u64 {
        /// x87 FPU/MMX State, note, must be '1'.
        X87 = 1 << 0,
        /// XSAVE feature set enable for MXCSR and XMM regs.
        SSE = 1 << 1,
        /// AVX enable and XSAVE feature set can be used to manage YMM regs.
        AVX = 1 << 2,
        /// MPX enable and XSAVE feature set can be used for BND regs.
        BNDREG = 1 << 3,
        /// PMX enable and XSAVE feature set can be used for BNDCFGU and BNDSTATUS regs.
        BNDCSR =  1 << 4,
        /// AVX-512 enable and XSAVE feature set can be used for AVX opmask, AKA k-mask, regs.
        OPMASK = 1 << 5,
        /// AVX-512 enable and XSAVE feature set can be used for upper-halves of the lower ZMM regs.
        ZMM_HI256 = 1 << 6,
        /// AVX-512 enable and XSAVE feature set can be used for the upper ZMM regs.
        HI16_ZMM = 1 << 7,
        /// XSAVE feature set can be used for PKRU register (part of protection keys mechanism).
        PKRU = 1 << 9,
        /// Control-flow Enforcement Technology (CET) user state.
        CETU = 1 << 11,
        /// Control-flow Enforcement Technology (CET) supervisor state.
        CETS = 1 << 12
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct XfrmWrapper(pub FlagSet<Xfrm>);

impl Default for XfrmWrapper {
    fn default() -> Self {
        XfrmWrapper(Xfrm::X87 | Xfrm::SSE)
    }
}

/// Section 38.7.1.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct Attributes {
    flags: FlagSet<Flags>,
    xfrm: XfrmWrapper,
}

impl From<FlagSet<Flags>> for Attributes {
    fn from(value: FlagSet<Flags>) -> Self {
        Self {
            flags: value,
            xfrm: Default::default(),
        }
    }
}

impl From<XfrmWrapper> for Attributes {
    fn from(value: XfrmWrapper) -> Self {
        Self {
            flags: Default::default(),
            xfrm: value,
        }
    }
}

impl Attributes {
    /// Creates new Attributes struct from Flags and Xfrm.
    pub const fn new(flags: FlagSet<Flags>, xfrm: XfrmWrapper) -> Self {
        Self { flags, xfrm }
    }

    /// Returns flags value of Attributes.
    pub const fn flags(&self) -> FlagSet<Flags> {
        self.flags
    }

    /// Returns xfrm value of Attributes.
    pub const fn xfrm(&self) -> XfrmWrapper {
        self.xfrm
    }

    /// Returns Attributes as a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        unsafe {
            let byte_slice = core::slice::from_raw_parts(
                &self as *const _ as *const u8,
                core::mem::size_of::<Self>(),
            );
            v.extend_from_slice(byte_slice);
        }
        v
    }
}

impl core::ops::Not for Attributes {
    type Output = Self;

    fn not(self) -> Self {
        Attributes {
            flags: !self.flags,
            xfrm: XfrmWrapper(!self.xfrm.0),
        }
    }
}

impl core::ops::BitAnd for Attributes {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Attributes {
            flags: self.flags & other.flags,
            xfrm: XfrmWrapper(self.xfrm.0 & other.xfrm.0),
        }
    }
}

impl core::ops::BitOr for Attributes {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Attributes {
            flags: self.flags | other.flags,
            xfrm: XfrmWrapper(self.xfrm.0 | other.xfrm.0),
        }
    }
}

impl core::ops::BitXor for Attributes {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        Attributes {
            flags: self.flags ^ other.flags,
            xfrm: XfrmWrapper(self.xfrm.0 ^ other.xfrm.0),
        }
    }
}

#[cfg(test)]
testaso! {
    struct Attributes: 4, 16 => {}
}
