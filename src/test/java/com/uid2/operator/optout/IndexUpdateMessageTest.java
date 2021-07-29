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

package com.uid2.operator.optout;

import com.uid2.operator.store.CloudSyncOptOutStore;
import com.uid2.shared.optout.OptOutUtils;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.assertEquals;

public class IndexUpdateMessageTest {

    @Test
    public void createEmpty_validateRoundTrip() {
        CloudSyncOptOutStore.IndexUpdateMessage in = new CloudSyncOptOutStore.IndexUpdateMessage();
        String json = in.toJsonString();
        CloudSyncOptOutStore.IndexUpdateMessage out = CloudSyncOptOutStore.IndexUpdateMessage.fromJsonString(json);
        assertEquals(in, out);
    }

    @Test
    public void createNonEmpty_validateRoundTrip() {
        CloudSyncOptOutStore.IndexUpdateMessage in = new CloudSyncOptOutStore.IndexUpdateMessage();
        in.addDeltaFile("someLog1");
        in.addDeltaFile("someLog2");
        in.addDeltaFile("someLog3");
        in.addPartitionFile("someSnapshot1");
        in.removeDeltaFile("someLog0");

        String json = in.toJsonString();
        CloudSyncOptOutStore.IndexUpdateMessage out = CloudSyncOptOutStore.IndexUpdateMessage.fromJsonString(json);
        assertEquals(in, out);
    }

    @Test
    public void createEmpty_validateLastTimestamp() {
        CloudSyncOptOutStore.IndexUpdateMessage iuc = new CloudSyncOptOutStore.IndexUpdateMessage();
        assertEquals(Instant.EPOCH, iuc.lastTimestamp());
    }

    @Test
    public void createNonEmpty1_validateLastTimestamp() {
        CloudSyncOptOutStore.IndexUpdateMessage iuc = new CloudSyncOptOutStore.IndexUpdateMessage();
        Instant ts1 = Instant.EPOCH.plusSeconds(1);
        Instant ts2 = Instant.EPOCH.plusSeconds(2);
        Instant ts3 = Instant.EPOCH.plusSeconds(3);
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts1));
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts3));
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts2));
        assertEquals(ts3, iuc.lastTimestamp());
    }

    @Test
    public void createNonEmpty2_validateLastTimestamp() {
        CloudSyncOptOutStore.IndexUpdateMessage iuc = new CloudSyncOptOutStore.IndexUpdateMessage();
        Instant ts1 = Instant.EPOCH.plusSeconds(1);
        Instant ts2 = Instant.EPOCH.plusSeconds(2);
        Instant ts3 = Instant.EPOCH.plusSeconds(3);
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts1));
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts3));
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts2));
        assertEquals(ts3, iuc.lastTimestamp());
    }

    @Test
    public void createNonEmpty3_validateLastTimestamp() {
        CloudSyncOptOutStore.IndexUpdateMessage iuc = new CloudSyncOptOutStore.IndexUpdateMessage();
        Instant ts1 = Instant.EPOCH.plusSeconds(1);
        Instant ts2 = Instant.EPOCH.plusSeconds(2);
        Instant ts3 = Instant.EPOCH.plusSeconds(3);
        Instant ts4 = Instant.EPOCH.plusSeconds(4);
        Instant ts5 = Instant.EPOCH.plusSeconds(5);
        Instant ts6 = Instant.EPOCH.plusSeconds(6);
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts1));
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts3));
        iuc.addPartitionFile(OptOutUtils.newPartitionFileName(ts2));
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts4));
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts6));
        iuc.addDeltaFile(OptOutUtils.newDeltaFileName(ts5));
        assertEquals(ts6, iuc.lastTimestamp());
    }
}
