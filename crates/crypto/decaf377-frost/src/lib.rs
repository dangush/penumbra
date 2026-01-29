//! Threshold signing for `decaf377-rdsa` signatures via FROST.
//!
//! This implementation only supports producing `SpendAuth` signatures, which
//! use the conventional `decaf377` basepoint.

// Requires nightly.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use anyhow::anyhow;
use frost_core as frost;
use penumbra_sdk_proto::crypto::decaf377_frost::v1 as pb;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// A FROST-related error.
pub type Error = frost_core::Error<traits::Decaf377Rdsa>;

use rand_core::{self, CryptoRng, RngCore};

mod hash;
pub mod keys;
mod traits;

use decaf377_rdsa::{Signature, SpendAuth};

// TODO: properly factor this code into leaf modules

// Below code copied from frost-ed25519 ("MIT or Apache-2.0")

type E = traits::Decaf377Rdsa;

/// A FROST participant identifier.
pub type Identifier = frost::Identifier<E>;

/// Signing round 1 functionality and types.
pub mod round1 {
    use crate::keys::SigningShare;
    use penumbra_sdk_proto::DomainType;

    use super::*;

    /// The nonces used for a single FROST signing ceremony.
    /// Published by each participant in the first round of the signing protocol.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    #[derive(Debug, Clone)]
    pub struct SigningNonces(pub(crate) frost::round1::SigningNonces<E>);

    impl From<SigningNonces> for pb::SigningNonces {
        fn from(value: SigningNonces) -> Self {
            Self {
                hiding: Some(pb::Nonce {
                    scalar: value.0.hiding().serialize(),
                }),
                binding: Some(pb::Nonce {
                    scalar: value.0.binding().serialize(),
                }),
            }
        }
    }

    impl TryFrom<pb::SigningNonces> for SigningNonces {
        type Error = anyhow::Error;

        fn try_from(value: pb::SigningNonces) -> Result<Self, Self::Error> {
            Ok(Self(frost::round1::SigningNonces::from_nonces(
                frost::round1::Nonce::deserialize(
                    value
                        .hiding
                        .ok_or(anyhow!("SigningNonces missing hiding"))?
                        .scalar,
                )?,
                frost::round1::Nonce::deserialize(
                    value
                        .binding
                        .ok_or(anyhow!("SigningNonces missing binding"))?
                        .scalar,
                )?,
            )))
        }
    }

    impl DomainType for SigningNonces {
        type Proto = pb::SigningNonces;
    }

    impl SigningNonces {
        /// Serialize to 64 bytes (hiding || binding)
        pub fn to_bytes(&self) -> [u8; 64] {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&self.0.hiding().serialize());
            bytes[32..].copy_from_slice(&self.0.binding().serialize());
            bytes
        }
    
        /// Deserialize from 64 bytes
        pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
            let hiding = frost::round1::Nonce::deserialize(bytes[..32].to_vec())?;
            let binding = frost::round1::Nonce::deserialize(bytes[32..].to_vec())?;
            Ok(Self(frost::round1::SigningNonces::from_nonces(hiding, binding)))
        }
    }

    impl Serialize for SigningNonces {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = self.to_bytes();
            if serializer.is_human_readable() {
                hex::encode(&bytes).serialize(serializer)
            } else {
                serializer.serialize_bytes(&bytes)
            }
        }
    }
    
    impl<'de> Deserialize<'de> for SigningNonces {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = if deserializer.is_human_readable() {
                let hex_str = String::deserialize(deserializer)?;
                hex::decode(&hex_str).map_err(serde::de::Error::custom)?
            } else {
                <Vec<u8>>::deserialize(deserializer)?
            };
            Self::from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
        }
    }

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    #[derive(Debug, Clone)]
    pub struct SigningCommitments(pub(crate) frost::round1::SigningCommitments<E>);

    impl From<SigningCommitments> for pb::SigningCommitments {
        fn from(value: SigningCommitments) -> Self {
            Self {
                hiding: Some(pb::NonceCommitment {
                    element: value.0.hiding().serialize(),
                }),
                binding: Some(pb::NonceCommitment {
                    element: value.0.binding().serialize(),
                }),
            }
        }
    }

    impl TryFrom<pb::SigningCommitments> for SigningCommitments {
        type Error = anyhow::Error;

        fn try_from(value: pb::SigningCommitments) -> Result<Self, Self::Error> {
            Ok(Self(frost::round1::SigningCommitments::new(
                frost::round1::NonceCommitment::deserialize(
                    value
                        .hiding
                        .ok_or(anyhow!("SigningCommitments missing hiding"))?
                        .element,
                )?,
                frost::round1::NonceCommitment::deserialize(
                    value
                        .binding
                        .ok_or(anyhow!("SigningCommitments missing binding"))?
                        .element,
                )?,
            )))
        }
    }

    impl DomainType for SigningCommitments {
        type Proto = pb::SigningCommitments;
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(secret: &SigningShare, rng: &mut RNG) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        let (a, b) = frost::round1::commit::<E, RNG>(secret, rng);
        (SigningNonces(a), SigningCommitments(b))
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
#[derive(Debug, Clone)]
pub struct SigningPackage(frost::SigningPackage<E>);

impl SigningPackage {
    /// Create a new `SigningPackage`
    ///
    /// The `signing_commitments` are sorted by participant `identifier`.
    pub fn new(
        signing_commitments: BTreeMap<Identifier, round1::SigningCommitments>,
        message: &[u8],
    ) -> Self {
        let signing_commitments = signing_commitments
            .into_iter()
            .map(|(a, b)| (a, b.0))
            .collect();
        Self(frost::SigningPackage::new(signing_commitments, message))
    }

    /// Get a signing commitment by its participant identifier, or None if not found.
    pub fn signing_commitment(
        &self,
        identifier: &Identifier,
    ) -> Option<round1::SigningCommitments> {
        self.0
            .signing_commitment(identifier)
            .map(round1::SigningCommitments)
    }
}

impl Serialize for SigningPackage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.serialize().map_err(serde::ser::Error::custom)?;
        // Serialize as hex string for human-readable formats
        if serializer.is_human_readable() {
            hex::encode(&bytes).serialize(serializer)
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for SigningPackage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let hex_str = <String>::deserialize(deserializer)?;
            hex::decode(&hex_str).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };
        let inner = frost::SigningPackage::deserialize(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(inner))
    }
}

/// Signing Round 2 functionality and types.
pub mod round2 {
    use frost_rerandomized::Randomizer;
    use penumbra_sdk_proto::DomainType;

    use super::*;

    /// A FROST participant's signature share, which the Coordinator will
    /// aggregate with all other signer's shares into the joint signature.
    #[derive(Debug, Clone)]
    pub struct SignatureShare(pub(crate) frost::round2::SignatureShare<E>);

    impl From<SignatureShare> for pb::SignatureShare {
        fn from(value: SignatureShare) -> Self {
            pb::SignatureShare {
                scalar: value.0.serialize(),
            }
        }
    }

    impl TryFrom<pb::SignatureShare> for SignatureShare {
        type Error = anyhow::Error;

        fn try_from(value: pb::SignatureShare) -> Result<Self, Self::Error> {
            Ok(Self(frost::round2::SignatureShare::deserialize(
                value.scalar,
            )?))
        }
    }

    impl DomainType for SignatureShare {
        type Proto = pb::SignatureShare;
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, Error> {
        frost::round2::sign(&signing_package.0, &signer_nonces.0, key_package).map(SignatureShare)
    }

    /// Like [`sign`], but for producing signatures with a randomized verification key.
    pub fn sign_randomized(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
        randomizer: decaf377::Fr,
    ) -> Result<SignatureShare, Error> {
        frost_rerandomized::sign(
            &signing_package.0,
            &signer_nonces.0,
            key_package,
            Randomizer::from_scalar(randomizer),
        )
        .map(SignatureShare)
    }
}

/// Verifies each FROST participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// The resulting signature is an ordinary Schnorr signature with normal
/// verification.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information).
///
/// Note that because the coordinator is trusted to report misbehaving parties
/// in order to avoid publishing an invalid signature, if the coordinator
/// themselves is a signer and misbehaves, they can avoid that step. However, at
/// worst, this results in a denial of service attack due to publishing an
/// invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &HashMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature<SpendAuth>, Error> {
    let signature_shares = signature_shares
        .iter()
        .map(|(a, b)| (*a, b.0.clone()))
        .collect();
    let frost_sig = frost::aggregate(&signing_package.0, &signature_shares, pubkeys)?;
    Ok(TryInto::<[u8; 64]>::try_into(frost_sig.serialize())
        .expect("serialization is valid")
        .into())
}

/// Like [`aggregate`], but for generating signatures with a randomized
/// verification key.
pub fn aggregate_randomized(
    signing_package: &SigningPackage,
    signature_shares: &HashMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
    randomizer: decaf377::Fr,
) -> Result<Signature<SpendAuth>, Error> {
    let signature_shares = signature_shares
        .iter()
        .map(|(a, b)| (*a, b.0.clone()))
        .collect();
    let frost_sig = frost_rerandomized::aggregate(
        &signing_package.0,
        &signature_shares,
        pubkeys,
        &frost_rerandomized::RandomizedParams::from_randomizer(
            pubkeys.verifying_key(),
            frost_rerandomized::Randomizer::from_scalar(randomizer),
        ),
    )?;
    Ok(TryInto::<[u8; 64]>::try_into(frost_sig.serialize())
        .expect("serialization is valid")
        .into())
}
