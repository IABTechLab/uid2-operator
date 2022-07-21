// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

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
