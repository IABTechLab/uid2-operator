package com.uid2.operator;

public class Const extends com.uid2.shared.Const {
    public class Config extends com.uid2.shared.Const.Config {
        public static final String ServiceInstancesProp = "service_instances";
        public static final String OptOutBloomFilterSizeProp = "optout_bloom_filter_size";
        public static final String OptOutHeapDefaultCapacityProp = "optout_heap_default_capacity";
        public static final String OptOutS3PathCompatProp = "optout_s3_path_compat";
        public static final String OptOutApiUriProp = "optout_api_uri";
        public static final String OptOutInMemCacheProp = "optout_inmem_cache";
        public static final String StorageMockProp = "storage_mock";
        public static final String StatsCollectorEventBus = "StatsCollector";
        public static final String FailureShutdownWaitHoursProp = "failure_shutdown_wait_hours";
        public static final String AllowLegacyAPIProp = "allow_legacy_api";
        public static final String SharingTokenExpiryProp = "sharing_token_expiry_seconds";
        public static final String MaxBidstreamLifetimeSecondsProp = "max_bidstream_lifetime_seconds";
        public static final String AllowClockSkewSecondsProp = "allow_clock_skew_seconds";
        public static final String MaxSharingLifetimeProp = "max_sharing_lifetime_seconds";
        public static final String EnableClientSideTokenGenerate = "client_side_token_generate";
        public static final String ValidateServiceLinks = "validate_service_links";
        public static final String OperatorTypeProp = "operator_type";
        public static final String EnclavePlatformProp = "enclave_platform";

        public static final String AzureVaultNameProp = "azure_vault_name";
        public static final String AzureSecretNameProp = "azure_secret_name";

        public static final String GcpSecretVersionNameProp = "gcp_secret_version_name";
        public static final String OptOutStatusApiEnabled = "optout_status_api_enabled";
        public static final String OptOutStatusMaxRequestSize = "optout_status_max_request_size";
        public static final String MaxInvalidPaths = "logging_limit_max_invalid_paths_per_interval";
        public static final String MaxVersionBucketsPerSite = "logging_limit_max_version_buckets_per_site";
    }
}
