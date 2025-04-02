package com.uid2.operator.store;

import com.uid2.operator.model.identities.FirstLevelHash;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Instant;

public interface IOptOutStore {

    /**
     * Get latest opt-out record
     *
     * @param firstLevelHash The first level hash of a DII Hash
     * @return The timestamp of latest opt-out record. <b>NULL</b> if no record.
     */
    Instant getLatestEntry(FirstLevelHash firstLevelHash);

    long getOptOutTimestampByAdId(String adId);

    void addEntry(FirstLevelHash firstLevelHash, byte[] advertisingId, Handler<AsyncResult<Instant>> handler);
}
