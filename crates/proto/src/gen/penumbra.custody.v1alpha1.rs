// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizeRequest {
    /// The transaction plan to authorize.
    #[prost(message, optional, tag="1")]
    pub plan: ::core::option::Option<super::super::core::transaction::v1alpha1::TransactionPlan>,
    /// Identifies the FVK (and hence the spend authorization key) to use for signing.
    #[prost(message, optional, tag="2")]
    pub account_group_id: ::core::option::Option<super::super::core::crypto::v1alpha1::AccountGroupId>,
    /// Optionally, pre-authorization data, if required by the custodian.
    ///
    /// Multiple `PreAuthorization` packets can be included in a single request,
    /// to support multi-party pre-authorizations.
    #[prost(message, repeated, tag="3")]
    pub pre_authorizations: ::prost::alloc::vec::Vec<PreAuthorization>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizeResponse {
    #[prost(message, optional, tag="1")]
    pub data: ::core::option::Option<super::super::core::transaction::v1alpha1::AuthorizationData>,
}
/// A pre-authorization packet.  This allows a custodian to delegate (partial)
/// signing authority to other authorization mechanisms.  Details of how a
/// custodian manages those keys are out-of-scope for the custody protocol and
/// are custodian-specific.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreAuthorization {
    #[prost(oneof="pre_authorization::PreAuthorization", tags="1")]
    pub pre_authorization: ::core::option::Option<pre_authorization::PreAuthorization>,
}
/// Nested message and enum types in `PreAuthorization`.
pub mod pre_authorization {
    /// An Ed25519-based preauthorization, containing an Ed25519 signature over the
    /// `TransactionPlan`.
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ed25519 {
        /// The Ed25519 verification key used to verify the signature.
        #[prost(bytes="vec", tag="1")]
        pub vk: ::prost::alloc::vec::Vec<u8>,
        /// The Ed25519 signature over the `TransactionPlan`.
        #[prost(bytes="vec", tag="2")]
        pub sig: ::prost::alloc::vec::Vec<u8>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum PreAuthorization {
        #[prost(message, tag="1")]
        Ed25519(Ed25519),
    }
}
/// Encoded file descriptor set for the `penumbra.custody.v1alpha1` package
pub const FILE_DESCRIPTOR_SET: &[u8] = &[
    0x0a, 0xfa, 0x18, 0x0a, 0x27, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2f, 0x63, 0x75,
    0x73, 0x74, 0x6f, 0x64, 0x79, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x63,
    0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x19, 0x70, 0x65,
    0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e, 0x76,
    0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x1a, 0x2a, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72,
    0x61, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x76, 0x31,
    0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x70, 0x72,
    0x6f, 0x74, 0x6f, 0x1a, 0x34, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2f, 0x63, 0x6f,
    0x72, 0x65, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76,
    0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x90, 0x02, 0x0a, 0x10, 0x41, 0x75,
    0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x47,
    0x0a, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x70,
    0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61,
    0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
    0x31, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6c, 0x61,
    0x6e, 0x52, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x12, 0x57, 0x0a, 0x10, 0x61, 0x63, 0x63, 0x6f, 0x75,
    0x6e, 0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
    0x0b, 0x32, 0x2d, 0x2e, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x6f, 0x72,
    0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
    0x31, 0x2e, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64,
    0x52, 0x0e, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64,
    0x12, 0x5a, 0x0a, 0x12, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x70,
    0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e,
    0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68,
    0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x11, 0x70, 0x72, 0x65, 0x41, 0x75,
    0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x5e, 0x0a, 0x11,
    0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
    0x65, 0x12, 0x49, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
    0x35, 0x2e, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
    0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c,
    0x70, 0x68, 0x61, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0xa5, 0x01, 0x0a,
    0x10, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x12, 0x4f, 0x0a, 0x07, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x18, 0x01, 0x20, 0x01,
    0x28, 0x0b, 0x32, 0x33, 0x2e, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75,
    0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x50,
    0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
    0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x48, 0x00, 0x52, 0x07, 0x65, 0x64, 0x32, 0x35, 0x35,
    0x31, 0x39, 0x1a, 0x2b, 0x0a, 0x07, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x12, 0x0e, 0x0a,
    0x02, 0x76, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x76, 0x6b, 0x12, 0x10, 0x0a,
    0x03, 0x73, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x73, 0x69, 0x67, 0x42,
    0x13, 0x0a, 0x11, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x32, 0x80, 0x01, 0x0a, 0x16, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79,
    0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
    0x66, 0x0a, 0x09, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x2b, 0x2e, 0x70,
    0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e,
    0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
    0x7a, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x70, 0x65, 0x6e, 0x75,
    0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e, 0x76, 0x31, 0x61,
    0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52,
    0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x8d, 0x02, 0x0a, 0x1d, 0x63, 0x6f, 0x6d, 0x2e,
    0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79,
    0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x42, 0x0c, 0x43, 0x75, 0x73, 0x74, 0x6f,
    0x64, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x58, 0x67, 0x69, 0x74, 0x68, 0x75,
    0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2d, 0x7a,
    0x6f, 0x6e, 0x65, 0x2f, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2f, 0x70, 0x72, 0x6f,
    0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x65, 0x6e, 0x75, 0x6d, 0x62,
    0x72, 0x61, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70,
    0x68, 0x61, 0x31, 0x3b, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x76, 0x31, 0x61, 0x6c, 0x70,
    0x68, 0x61, 0x31, 0xa2, 0x02, 0x03, 0x50, 0x43, 0x58, 0xaa, 0x02, 0x19, 0x50, 0x65, 0x6e, 0x75,
    0x6d, 0x62, 0x72, 0x61, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x2e, 0x56, 0x31, 0x61,
    0x6c, 0x70, 0x68, 0x61, 0x31, 0xca, 0x02, 0x19, 0x50, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61,
    0x5c, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
    0x31, 0xe2, 0x02, 0x25, 0x50, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x5c, 0x43, 0x75, 0x73,
    0x74, 0x6f, 0x64, 0x79, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x5c, 0x47, 0x50,
    0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1b, 0x50, 0x65, 0x6e, 0x75,
    0x6d, 0x62, 0x72, 0x61, 0x3a, 0x3a, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x3a, 0x3a, 0x56,
    0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x4a, 0x9b, 0x10, 0x0a, 0x06, 0x12, 0x04, 0x00, 0x00,
    0x38, 0x01, 0x0a, 0x08, 0x0a, 0x01, 0x0c, 0x12, 0x03, 0x00, 0x00, 0x12, 0x0a, 0x08, 0x0a, 0x01,
    0x02, 0x12, 0x03, 0x02, 0x00, 0x22, 0x0a, 0x09, 0x0a, 0x02, 0x03, 0x00, 0x12, 0x03, 0x04, 0x00,
    0x34, 0x0a, 0x09, 0x0a, 0x02, 0x03, 0x01, 0x12, 0x03, 0x05, 0x00, 0x3e, 0x0a, 0xb2, 0x04, 0x0a,
    0x02, 0x06, 0x00, 0x12, 0x04, 0x12, 0x00, 0x15, 0x01, 0x1a, 0xa5, 0x04, 0x20, 0x54, 0x68, 0x65,
    0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
    0x6c, 0x20, 0x69, 0x73, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x61, 0x20, 0x77,
    0x61, 0x6c, 0x6c, 0x65, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20,
    0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6f, 0x72, 0x0a, 0x20, 0x61, 0x20, 0x74, 0x72, 0x61,
    0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x79, 0x27, 0x76, 0x65,
    0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x65, 0x64, 0x2e, 0x0a, 0x0a, 0x20,
    0x4d, 0x6f, 0x64, 0x65, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x20, 0x61, 0x73, 0x20, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x79, 0x6e, 0x63, 0x68, 0x72,
    0x6f, 0x6e, 0x6f, 0x75, 0x73, 0x20, 0x52, 0x50, 0x43, 0x20, 0x63, 0x61, 0x6c, 0x6c, 0x20, 0x65,
    0x6e, 0x63, 0x6f, 0x75, 0x72, 0x61, 0x67, 0x65, 0x73, 0x0a, 0x20, 0x73, 0x6f, 0x66, 0x74, 0x77,
    0x61, 0x72, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x77, 0x72, 0x69, 0x74, 0x74, 0x65,
    0x6e, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x77, 0x61, 0x79, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
    0x68, 0x61, 0x73, 0x20, 0x61, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69, 0x62, 0x6c, 0x65,
    0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6c, 0x6f, 0x77, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
    0x61, 0x20, 0x22, 0x73, 0x6f, 0x66, 0x74, 0x0a, 0x20, 0x48, 0x53, 0x4d, 0x22, 0x2c, 0x20, 0x74,
    0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
    0x2c, 0x20, 0x61, 0x20, 0x68, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72, 0x65, 0x20, 0x77, 0x61, 0x6c,
    0x6c, 0x65, 0x74, 0x2c, 0x20, 0x65, 0x74, 0x63, 0x2e, 0x0a, 0x0a, 0x20, 0x54, 0x68, 0x65, 0x20,
    0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
    0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x74, 0x72, 0x75, 0x73, 0x74, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x75,
    0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x20, 0x73, 0x70, 0x65, 0x6e, 0x64, 0x73, 0x2c, 0x20,
    0x73, 0x6f, 0x0a, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x20, 0x72, 0x65, 0x71, 0x75,
    0x65, 0x73, 0x74, 0x73, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69,
    0x6e, 0x20, 0x73, 0x75, 0x66, 0x66, 0x69, 0x63, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x66,
    0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x69, 0x61, 0x6e, 0x20, 0x74, 0x6f, 0x0a, 0x20, 0x75,
    0x6e, 0x64, 0x65, 0x72, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x72,
    0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x64, 0x65,
    0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x65, 0x20, 0x77, 0x68, 0x65, 0x74, 0x68, 0x65, 0x72, 0x20,
    0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x69, 0x74, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64,
    0x20, 0x62, 0x65, 0x0a, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x2e,
    0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x06, 0x00, 0x01, 0x12, 0x03, 0x12, 0x08, 0x1e, 0x0a, 0x54, 0x0a,
    0x04, 0x06, 0x00, 0x02, 0x00, 0x12, 0x03, 0x14, 0x02, 0x3e, 0x1a, 0x47, 0x20, 0x52, 0x65, 0x71,
    0x75, 0x65, 0x73, 0x74, 0x73, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x72, 0x61, 0x6e, 0x73,
    0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x67, 0x69, 0x76, 0x65, 0x6e, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
    0x6e, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x06, 0x00, 0x02, 0x00, 0x01, 0x12, 0x03, 0x14, 0x06,
    0x0f, 0x0a, 0x0c, 0x0a, 0x05, 0x06, 0x00, 0x02, 0x00, 0x02, 0x12, 0x03, 0x14, 0x10, 0x20, 0x0a,
    0x0c, 0x0a, 0x05, 0x06, 0x00, 0x02, 0x00, 0x03, 0x12, 0x03, 0x14, 0x2b, 0x3c, 0x0a, 0x0a, 0x0a,
    0x02, 0x04, 0x00, 0x12, 0x04, 0x17, 0x00, 0x22, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x00, 0x01,
    0x12, 0x03, 0x17, 0x08, 0x18, 0x0a, 0x31, 0x0a, 0x04, 0x04, 0x00, 0x02, 0x00, 0x12, 0x03, 0x19,
    0x02, 0x35, 0x1a, 0x24, 0x20, 0x54, 0x68, 0x65, 0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x20, 0x70, 0x6c, 0x61, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x75, 0x74,
    0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x00,
    0x06, 0x12, 0x03, 0x19, 0x02, 0x2b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x00, 0x01, 0x12,
    0x03, 0x19, 0x2c, 0x30, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x00, 0x03, 0x12, 0x03, 0x19,
    0x33, 0x34, 0x0a, 0x5d, 0x0a, 0x04, 0x04, 0x00, 0x02, 0x01, 0x12, 0x03, 0x1b, 0x02, 0x3b, 0x1a,
    0x50, 0x20, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x46, 0x56, 0x4b, 0x20, 0x28, 0x61, 0x6e, 0x64, 0x20, 0x68, 0x65, 0x6e, 0x63, 0x65, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x73, 0x70, 0x65, 0x6e, 0x64, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72,
    0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x29, 0x20, 0x74, 0x6f, 0x20,
    0x75, 0x73, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e,
    0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x01, 0x06, 0x12, 0x03, 0x1b, 0x02, 0x25, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x01, 0x01, 0x12, 0x03, 0x1b, 0x26, 0x36, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x00, 0x02, 0x01, 0x03, 0x12, 0x03, 0x1b, 0x39, 0x3a, 0x0a, 0xc8, 0x01, 0x0a, 0x04,
    0x04, 0x00, 0x02, 0x02, 0x12, 0x03, 0x21, 0x02, 0x33, 0x1a, 0xba, 0x01, 0x20, 0x4f, 0x70, 0x74,
    0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x70, 0x72, 0x65, 0x2d, 0x61, 0x75, 0x74,
    0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2c,
    0x20, 0x69, 0x66, 0x20, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x69, 0x61, 0x6e, 0x2e, 0x0a, 0x0a,
    0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c, 0x65, 0x20, 0x60, 0x50, 0x72, 0x65, 0x41, 0x75,
    0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x60, 0x20, 0x70, 0x61, 0x63,
    0x6b, 0x65, 0x74, 0x73, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x69, 0x6e, 0x63, 0x6c,
    0x75, 0x64, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65,
    0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2c, 0x0a, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x75,
    0x70, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x70, 0x61, 0x72, 0x74,
    0x79, 0x20, 0x70, 0x72, 0x65, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x04, 0x12,
    0x03, 0x21, 0x02, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x06, 0x12, 0x03, 0x21,
    0x0b, 0x1b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x01, 0x12, 0x03, 0x21, 0x1c, 0x2e,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x03, 0x12, 0x03, 0x21, 0x31, 0x32, 0x0a, 0x0a,
    0x0a, 0x02, 0x04, 0x01, 0x12, 0x04, 0x24, 0x00, 0x26, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x01,
    0x01, 0x12, 0x03, 0x24, 0x08, 0x19, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x01, 0x02, 0x00, 0x12, 0x03,
    0x25, 0x02, 0x37, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x06, 0x12, 0x03, 0x25, 0x02,
    0x2d, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x01, 0x12, 0x03, 0x25, 0x2e, 0x32, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x03, 0x12, 0x03, 0x25, 0x35, 0x36, 0x0a, 0x86, 0x02,
    0x0a, 0x02, 0x04, 0x02, 0x12, 0x04, 0x2c, 0x00, 0x38, 0x01, 0x1a, 0xf9, 0x01, 0x20, 0x41, 0x20,
    0x70, 0x72, 0x65, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x20, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20,
    0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x73, 0x20, 0x61, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x69,
    0x61, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x20, 0x28,
    0x70, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x29, 0x0a, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e,
    0x67, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x6f,
    0x74, 0x68, 0x65, 0x72, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x20, 0x6d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x73, 0x6d, 0x73, 0x2e, 0x20, 0x20,
    0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x68, 0x6f, 0x77, 0x20, 0x61,
    0x0a, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x69, 0x61, 0x6e, 0x20, 0x6d, 0x61, 0x6e, 0x61,
    0x67, 0x65, 0x73, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x73, 0x20, 0x61,
    0x72, 0x65, 0x20, 0x6f, 0x75, 0x74, 0x2d, 0x6f, 0x66, 0x2d, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x79, 0x20,
    0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x20, 0x61, 0x6e, 0x64, 0x0a, 0x20, 0x61, 0x72,
    0x65, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x64, 0x69, 0x61, 0x6e, 0x2d, 0x73, 0x70, 0x65, 0x63,
    0x69, 0x66, 0x69, 0x63, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x02, 0x01, 0x12, 0x03, 0x2c,
    0x08, 0x18, 0x0a, 0x6f, 0x0a, 0x04, 0x04, 0x02, 0x03, 0x00, 0x12, 0x04, 0x2f, 0x02, 0x34, 0x03,
    0x1a, 0x61, 0x20, 0x41, 0x6e, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x2d, 0x62, 0x61,
    0x73, 0x65, 0x64, 0x20, 0x70, 0x72, 0x65, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67,
    0x20, 0x61, 0x6e, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x0a, 0x20,
    0x60, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x6e,
    0x60, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x03, 0x00, 0x01, 0x12, 0x03, 0x2f, 0x0a,
    0x11, 0x0a, 0x4b, 0x0a, 0x06, 0x04, 0x02, 0x03, 0x00, 0x02, 0x00, 0x12, 0x03, 0x31, 0x04, 0x11,
    0x1a, 0x3c, 0x20, 0x54, 0x68, 0x65, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x76,
    0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x20,
    0x75, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x0a, 0x0a, 0x0e,
    0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x00, 0x05, 0x12, 0x03, 0x31, 0x04, 0x09, 0x0a, 0x0e,
    0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x00, 0x01, 0x12, 0x03, 0x31, 0x0a, 0x0c, 0x0a, 0x0e,
    0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x00, 0x03, 0x12, 0x03, 0x31, 0x0f, 0x10, 0x0a, 0x42,
    0x0a, 0x06, 0x04, 0x02, 0x03, 0x00, 0x02, 0x01, 0x12, 0x03, 0x33, 0x04, 0x12, 0x1a, 0x33, 0x20,
    0x54, 0x68, 0x65, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x60,
    0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x6e, 0x60,
    0x2e, 0x0a, 0x0a, 0x0e, 0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x01, 0x05, 0x12, 0x03, 0x33,
    0x04, 0x09, 0x0a, 0x0e, 0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x01, 0x01, 0x12, 0x03, 0x33,
    0x0a, 0x0d, 0x0a, 0x0e, 0x0a, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x01, 0x03, 0x12, 0x03, 0x33,
    0x10, 0x11, 0x0a, 0x0c, 0x0a, 0x04, 0x04, 0x02, 0x08, 0x00, 0x12, 0x04, 0x35, 0x02, 0x37, 0x03,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x08, 0x00, 0x01, 0x12, 0x03, 0x35, 0x08, 0x19, 0x0a, 0x0b,
    0x0a, 0x04, 0x04, 0x02, 0x02, 0x00, 0x12, 0x03, 0x36, 0x04, 0x18, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x02, 0x02, 0x00, 0x06, 0x12, 0x03, 0x36, 0x04, 0x0b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02,
    0x00, 0x01, 0x12, 0x03, 0x36, 0x0c, 0x13, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x03,
    0x12, 0x03, 0x36, 0x16, 0x17, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
];
include!("penumbra.custody.v1alpha1.tonic.rs");
// @@protoc_insertion_point(module)