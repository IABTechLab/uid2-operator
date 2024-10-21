package com.uid2.operator.store;

import com.uid2.operator.model.userIdentity.FirstLevelHashIdentity;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Instant;

public interface IOptOutStore {

    /**
     * Get latest opt-out record
     *
     * @param firstLevelHashIdentity The first level hash of a DII Hash
     * @return The timestamp of latest opt-out record. <b>NULL</b> if no record.
     */
    Instant getLatestEntry(FirstLevelHashIdentity firstLevelHashIdentity);

    long getOptOutTimestampByAdId(String adId);

    void addEntry(FirstLevelHashIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler);
}
