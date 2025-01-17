/// Specifies fees paid by a transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fee {
    /// The amount of the token used to pay fees.
    #[prost(message, optional, tag = "1")]
    pub amount: ::core::option::Option<super::super::super::num::v1::Amount>,
    /// If present, the asset ID of the token used to pay fees.
    /// If absent, specifies the staking token implicitly.
    #[prost(message, optional, tag = "2")]
    pub asset_id: ::core::option::Option<super::super::super::asset::v1::AssetId>,
}
impl ::prost::Name for Fee {
    const NAME: &'static str = "Fee";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Gas usage for a transaction.
///
/// Gas used is multiplied by `GasPrices` to determine a `Fee`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gas {
    /// The amount of block space used.
    #[prost(uint64, tag = "1")]
    pub block_space: u64,
    /// The amount of compact block space used.
    #[prost(uint64, tag = "2")]
    pub compact_block_space: u64,
    /// The amount of verification cost used.
    #[prost(uint64, tag = "3")]
    pub verification: u64,
    /// The amount of execution cost used.
    #[prost(uint64, tag = "4")]
    pub execution: u64,
}
impl ::prost::Name for Gas {
    const NAME: &'static str = "Gas";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GasPrices {
    /// The asset ID of the fee token these prices are for.
    ///
    /// If absent, specifies the staking token implicitly.
    #[prost(message, optional, tag = "15")]
    pub asset_id: ::core::option::Option<super::super::super::asset::v1::AssetId>,
    /// The price per unit block space in terms of the staking token, with an implicit 1,000 denominator.
    #[prost(uint64, tag = "1")]
    pub block_space_price: u64,
    /// The price per unit compact block space in terms of the staking token, with an implicit 1,000 denominator.
    #[prost(uint64, tag = "2")]
    pub compact_block_space_price: u64,
    /// The price per unit verification cost in terms of the staking token, with an implicit 1,000 denominator.
    #[prost(uint64, tag = "3")]
    pub verification_price: u64,
    /// The price per unit execution cost in terms of the staking token, with an implicit 1,000 denominator.
    #[prost(uint64, tag = "4")]
    pub execution_price: u64,
}
impl ::prost::Name for GasPrices {
    const NAME: &'static str = "GasPrices";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeeTier {
    /// The selected fee tier.
    #[prost(enumeration = "fee_tier::Tier", tag = "1")]
    pub fee_tier: i32,
}
/// Nested message and enum types in `FeeTier`.
pub mod fee_tier {
    /// The tier for the fee.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Tier {
        Unspecified = 0,
        Low = 1,
        Medium = 2,
        High = 3,
    }
    impl Tier {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Tier::Unspecified => "TIER_UNSPECIFIED",
                Tier::Low => "TIER_LOW",
                Tier::Medium => "TIER_MEDIUM",
                Tier::High => "TIER_HIGH",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "TIER_UNSPECIFIED" => Some(Self::Unspecified),
                "TIER_LOW" => Some(Self::Low),
                "TIER_MEDIUM" => Some(Self::Medium),
                "TIER_HIGH" => Some(Self::High),
                _ => None,
            }
        }
    }
}
impl ::prost::Name for FeeTier {
    const NAME: &'static str = "FeeTier";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Fee component configuration data.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeeParameters {
    /// Fixed gas prices in the native token used to compute transactions' base
    /// fees.
    ///
    /// In the future, this should be removed and replaced with parameters for
    /// dynamic gas pricing.
    #[prost(message, optional, tag = "1")]
    pub fixed_gas_prices: ::core::option::Option<GasPrices>,
    /// Fixed gas prices in other tokens used to compute transactions' base fees.
    ///
    /// In the future, this should be removed and replaced with fixed multiples of
    /// the native token's price (so that there is one set of dynamically
    /// determined gas prices in the native token, and derived gas prices in other
    /// alternative tokens).
    ///
    /// If this is empty, no other tokens are accepted for gas.
    #[prost(message, repeated, tag = "2")]
    pub fixed_alt_gas_prices: ::prost::alloc::vec::Vec<GasPrices>,
}
impl ::prost::Name for FeeParameters {
    const NAME: &'static str = "FeeParameters";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Fee-specific genesis content.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisContent {
    /// The FeeParameters present at genesis.
    #[prost(message, optional, tag = "1")]
    pub fee_params: ::core::option::Option<FeeParameters>,
}
impl ::prost::Name for GenesisContent {
    const NAME: &'static str = "GenesisContent";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CurrentGasPricesRequest {}
impl ::prost::Name for CurrentGasPricesRequest {
    const NAME: &'static str = "CurrentGasPricesRequest";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CurrentGasPricesResponse {
    /// The current gas prices, in the preferred (native) token.
    #[prost(message, optional, tag = "1")]
    pub gas_prices: ::core::option::Option<GasPrices>,
    /// Other gas prices for other accepted tokens.
    #[prost(message, repeated, tag = "2")]
    pub alt_gas_prices: ::prost::alloc::vec::Vec<GasPrices>,
}
impl ::prost::Name for CurrentGasPricesResponse {
    const NAME: &'static str = "CurrentGasPricesResponse";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Emitted during fee payment.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventPaidFee {
    /// The fee paid.
    #[prost(message, optional, tag = "1")]
    pub fee: ::core::option::Option<Fee>,
    /// The base fee that was required.
    #[prost(message, optional, tag = "2")]
    pub base_fee: ::core::option::Option<Fee>,
    /// The tip that was paid to the proposer.
    #[prost(message, optional, tag = "3")]
    pub tip: ::core::option::Option<Fee>,
    /// The gas used to compute the base fee.
    #[prost(message, optional, tag = "4")]
    pub gas_used: ::core::option::Option<Gas>,
}
impl ::prost::Name for EventPaidFee {
    const NAME: &'static str = "EventPaidFee";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Emitted as a summary of fees in the block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventBlockFees {
    /// The total fees, after swapping to the native token.
    #[prost(message, optional, tag = "1")]
    pub swapped_fee_total: ::core::option::Option<Fee>,
    /// The total base fees, after swapping to the native token.
    #[prost(message, optional, tag = "2")]
    pub swapped_base_fee_total: ::core::option::Option<Fee>,
    /// The total tips, after swapping to the native token.
    #[prost(message, optional, tag = "3")]
    pub swapped_tip_total: ::core::option::Option<Fee>,
}
impl ::prost::Name for EventBlockFees {
    const NAME: &'static str = "EventBlockFees";
    const PACKAGE: &'static str = "penumbra.core.component.fee.v1";
    fn full_name() -> ::prost::alloc::string::String {
        ::prost::alloc::format!("penumbra.core.component.fee.v1.{}", Self::NAME)
    }
}
/// Generated client implementations.
#[cfg(feature = "rpc")]
pub mod query_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// Query operations for the fee component.
    #[derive(Debug, Clone)]
    pub struct QueryServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl QueryServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> QueryServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> QueryServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            QueryServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Get the current gas prices.
        pub async fn current_gas_prices(
            &mut self,
            request: impl tonic::IntoRequest<super::CurrentGasPricesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CurrentGasPricesResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/penumbra.core.component.fee.v1.QueryService/CurrentGasPrices",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "penumbra.core.component.fee.v1.QueryService",
                        "CurrentGasPrices",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
#[cfg(feature = "rpc")]
pub mod query_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with QueryServiceServer.
    #[async_trait]
    pub trait QueryService: Send + Sync + 'static {
        /// Get the current gas prices.
        async fn current_gas_prices(
            &self,
            request: tonic::Request<super::CurrentGasPricesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CurrentGasPricesResponse>,
            tonic::Status,
        >;
    }
    /// Query operations for the fee component.
    #[derive(Debug)]
    pub struct QueryServiceServer<T: QueryService> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: QueryService> QueryServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for QueryServiceServer<T>
    where
        T: QueryService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/penumbra.core.component.fee.v1.QueryService/CurrentGasPrices" => {
                    #[allow(non_camel_case_types)]
                    struct CurrentGasPricesSvc<T: QueryService>(pub Arc<T>);
                    impl<
                        T: QueryService,
                    > tonic::server::UnaryService<super::CurrentGasPricesRequest>
                    for CurrentGasPricesSvc<T> {
                        type Response = super::CurrentGasPricesResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CurrentGasPricesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as QueryService>::current_gas_prices(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CurrentGasPricesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: QueryService> Clone for QueryServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: QueryService> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: QueryService> tonic::server::NamedService for QueryServiceServer<T> {
        const NAME: &'static str = "penumbra.core.component.fee.v1.QueryService";
    }
}
