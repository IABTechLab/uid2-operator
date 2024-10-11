package com.uid2.operator.store;

import com.uid2.operator.model.FirstLevelHashIdentity;
import com.uid2.operator.model.HashedDiiIdentity;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Instant;

public interface IOptOutStore {

    /**
     * Get latest Opt-out record with respect to the UID (hashed identity)
     *
     * @param firstLevelHashIdentity@return The timestamp of latest opt-out record. <b>NULL</b> if no record.
     */
    Instant getLatestEntry(FirstLevelHashIdentity firstLevelHashIdentity);

    long getOptOutTimestampByAdId(String adId);

    void addEntry(FirstLevelHashIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler);
}
