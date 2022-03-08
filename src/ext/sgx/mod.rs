// SPDX-License-Identifier: Apache-2.0

mod attestation_types;
mod types;

use crate::crypto::*;

use std::fmt::Debug;

use anyhow::{anyhow, Context, Result};
use attestation_types::quote::Quote;
use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
use const_oid::ObjectIdentifier;
use der::{Decodable, Sequence};
use pkcs8::AlgorithmIdentifier;
use x509::{ext::Extension, request::CertReqInfo, Certificate, PkiPath, TbsCertificate};

use super::ExtVerifier;
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Evidence<'a> {
    pub pck: Certificate<'a>,

    #[asn1(type = "OCTET STRING")]
    pub quote: &'a [u8],
}

#[derive(Clone, Debug, Default)]
pub struct Sgx(());

impl Sgx {
    const ROOT: &'static [u8] = include_bytes!("sgx.pkipath");

    // This ensures that the supplied pck is rooted in our trusted chain.
    fn is_trusted<'c>(&self, pck: &'c Certificate<'c>) -> Result<&'c TbsCertificate<'c>> {
        let path = PkiPath::from_der(Self::ROOT)?;

        let mut signer = Some(&path.0[0].tbs_certificate);
        for cert in path.0.iter().chain([pck].into_iter()) {
            signer = signer.and_then(|s| s.verify_crt(cert).ok());
        }

        if let Some(signer) = signer {
            if signer == &pck.tbs_certificate {
                return Ok(&pck.tbs_certificate);
            }
        }

        Err(anyhow!("sgx pck is untrusted"))
    }
}

impl ExtVerifier for Sgx {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    const ATT: bool = true;

    fn verify(&self, cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("snp extension cannot be critical"));
        }

        // Decode the evidence.
        let evidence = Evidence::from_der(ext.extn_value)?;

        // Validate the PCK.
        let pck = self.is_trusted(&evidence.pck)?;

        // Force certs to have the same key type as the PCK.
        //
        // A note about this check is in order. We don't want to build crypto
        // algorithm negotiation into this protocol. Not only is it complex
        // but it is also subject to downgrade attacks. For example, if the
        // weakest link in the certificate chain is a P384 key and the
        // attacker downgrades the negotiation to P256, it has just weakened
        // security for the whole chain.
        //
        // We solve this by using forcing the certification request to have
        // the same key type as the VCEK. This means we have no worse security
        // than whatever AMD chose for the VCEK.
        //
        // Additionally, we do this check early to be defensive.
        if cri.public_key.algorithm != pck.subject_public_key_info.algorithm {
            return Err(anyhow!("sgx pck algorithm mismatch"));
        }

        // Extract the quote and its signature.
        let quote = Quote::try_from(evidence.quote).context("sgx quote parse error")?;

        let body: [u8; 384] = unsafe { std::mem::transmute(*quote.body()) };
        let signature = quote
            .sigdata()
            .report_sig()
            .to_der()
            .context("sgx quote signature parse error")?;

        pck.verify_raw(
            &body,
            AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            &signature,
        )
        .unwrap();
        // .context("sgx quote contains invalid signature")?;

        // TODO: validate report
        if !dbg {}

        Ok(true)
    }
}

#[macro_export]
macro_rules! testaso {
    (@off $name:path=>$field:ident) => {
        memoffset::offset_of!($name, $field)
    };

    ($(struct $name:path: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
        #[cfg(test)]
        #[test]
        fn align() {
            use core::mem::align_of;

            $(
                assert_eq!(
                    align_of::<$name>(),
                    $align,
                    "align: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn size() {
            use core::mem::size_of;

            $(
                assert_eq!(
                    size_of::<$name>(),
                    $size,
                    "size: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn offsets() {
            $(
                $(
                    assert_eq!(
                        testaso!(@off $name=>$field),
                        $offset,
                        "offset: {}::{}",
                        stringify!($name),
                        stringify!($field)
                    );
                )*
            )+
        }
    };
}
