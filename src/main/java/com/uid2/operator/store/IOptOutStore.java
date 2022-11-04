package com.uid2.operator.store;

import com.uid2.operator.model.UserIdentity;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Instant;

public interface IOptOutStore {

    Instant getLatestEntry(UserIdentity firstLevelHashIdentity);

    void addEntry(UserIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler);
}
