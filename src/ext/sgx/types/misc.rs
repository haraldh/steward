// SPDX-License-Identifier: Apache-2.0

//! MiscSelect (Section 38.7.2)
//! The bit vector of MISCSELECT selects which extended information is to be saved in the MISC
//! region of the SSA frame when an AEX is generated.

use flagset::flags;
#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

flags! {
    /// Section 38.7.2
    #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
    pub enum MiscSelect: u32 {
        /// Report info about page faults and general protection exception that occurred inside an enclave.
        EXINFO = 1 << 0
    }
}
