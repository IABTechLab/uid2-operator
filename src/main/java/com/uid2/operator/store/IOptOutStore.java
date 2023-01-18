package com.uid2.operator.store;

import com.uid2.operator.model.UserIdentity;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Instant;

public interface IOptOutStore {

    /**
     * Get latest Opt-out record with respect to the UID (hashed identity)
     * @param firstLevelHashIdentity UID
     * @return The timestamp of latest opt-out record. <b>NULL</b> if no record.
     */
    Instant getLatestEntry(UserIdentity firstLevelHashIdentity);

    void addEntry(UserIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler);
}
