package com.uid2.operator;

public class Const extends com.uid2.shared.Const {
    public class Config extends com.uid2.shared.Const.Config {
        public static final String ServiceInstancesProp = "service_instances";
        public static final String OptOutBloomFilterSizeProp = "optout_bloom_filter_size";
        public static final String OptOutHeapDefaultCapacityProp = "optout_heap_default_capacity";
        public static final String OptOutS3PathCompatProp = "optout_s3_path_compat";
        public static final String OptOutApiTokenProp = "optout_api_token";
        public static final String OptOutApiUriProp = "optout_api_uri";
        public static final String OptOutInMemCacheProp = "optout_inmem_cache";
        public static final String StorageMockProp = "storage_mock";
        public static final String StatsCollectorEventBus = "StatsCollector";
        public static final String FailureShutdownWaitHoursProp = "failure_shutdown_wait_hours";
        public static final String AllowLegacyAPIProp = "allow_legacy_api";
    }
}
