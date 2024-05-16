package com.uid2.operator.store;

import com.uid2.operator.Const;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.cloud.MemCachedStorage;
import com.uid2.shared.optout.OptOutConst;
import com.uid2.shared.optout.OptOutEntry;
import com.uid2.shared.optout.OptOutUtils;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;

class OptOutStoreSnapshotTest {
    @Nested
    class GetAdIdOptOutTimestamp {
        @Test
        void emptySnapshotReturnsNegativeOne() {
            DownloadCloudStorage fsStore = mock(DownloadCloudStorage.class);
            JsonObject config = make1mOptOutEntryConfig(true);
            CloudSyncOptOutStore.OptOutStoreSnapshot snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(fsStore, config, Clock.systemUTC());
            assertEquals(-1L, snapshot.getAdIdOptOutTimestamp(OptOutEntry.newRandom().advertisingIdToB64()));
        }

        @ParameterizedTest
        @CsvSource({
                "1,1",
                "10,1",
                "10,10"
        })
        void emptySnapshotUpdatedWithDeltaFilesReturnsCorrectTimestamps(int deltaFileCount, int entriesPerDeltaFileCount) throws CloudStorageException, IOException {
            assumeTrue(deltaFileCount > 0);
            assumeTrue(entriesPerDeltaFileCount > 0);

            // Arrange
            Clock clock = Clock.fixed(Instant.parse("2024-05-06T10:15:30.00Z"), ZoneOffset.UTC);

            MemCachedStorage fsStore = new MemCachedStorage();

            List<OptOutEntry> entries = new ArrayList<>();

            for (int i = 0; i < deltaFileCount; i++) {
                Instant deltaFileTimestamp = clock.instant()
                        .minus(deltaFileCount, ChronoUnit.HOURS);

                List<OptOutEntry> deltaEntries = createDelta(entriesPerDeltaFileCount, deltaFileTimestamp, fsStore);
                entries.addAll(deltaEntries);
            }

            Set<String> paths = new HashSet<>(fsStore.list(OptOutUtils.prefixDeltaFile));

            JsonObject config = make1mOptOutEntryConfig(true);

            // Act
            CloudSyncOptOutStore.OptOutStoreSnapshot snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(fsStore, config, clock)
                    .updateIndex(paths);

            // Assert
            for (OptOutEntry entry : entries) {
                assertEquals(entry.timestamp, snapshot.getAdIdOptOutTimestamp(entry.advertisingIdToB64()));
            }
        }

        @ParameterizedTest
        @CsvSource({
                "1,1",
                "10,1",
                "10,10"
        })
        void emptySnapshotUpdatedWithPartitionFilesReturnsCorrectTimestamps(int partitionFileCount, int entriesPerPartitionFileCount) throws CloudStorageException, IOException {
            assumeTrue(partitionFileCount > 0);
            assumeTrue(entriesPerPartitionFileCount > 0);

            // Arrange
            Clock clock = Clock.fixed(Instant.parse("2024-05-06T10:15:30.00Z"), ZoneOffset.UTC);

            MemCachedStorage fsStore = new MemCachedStorage();

            List<OptOutEntry> entries = new ArrayList<>();

            for (int i = 0; i < partitionFileCount; i++) {
                Instant partitionTimestamp = clock.instant()
                        .minus(i, ChronoUnit.DAYS);

                List<OptOutEntry> partitionEntries = createPartition(entriesPerPartitionFileCount, partitionTimestamp, fsStore);
                entries.addAll(partitionEntries);
            }

            Set<String> paths = new HashSet<>(fsStore.list(OptOutUtils.prefixPartitionFile));

            JsonObject config = make1mOptOutEntryConfig(true);

            // Act
            CloudSyncOptOutStore.OptOutStoreSnapshot snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(fsStore, config, clock)
                    .updateIndex(paths);

            // Assert
            for (OptOutEntry entry : entries) {
                assertEquals(entry.timestamp, snapshot.getAdIdOptOutTimestamp(entry.advertisingIdToB64()));
            }
        }

        @Test
        void optoutStatusApiDisabled()  throws CloudStorageException, IOException {
            int entriesPerPartitionFileCount = 10;
            MemCachedStorage fsStore = new MemCachedStorage();

            Clock clock = Clock.fixed(Instant.parse("2024-05-06T10:15:30.00Z"), ZoneOffset.UTC);
            List<OptOutEntry> entries = createPartition(entriesPerPartitionFileCount, clock.instant(), fsStore);

            Set<String> paths = new HashSet<>(fsStore.list(OptOutUtils.prefixPartitionFile));

            JsonObject config = make1mOptOutEntryConfig(false);

            // Act
            CloudSyncOptOutStore.OptOutStoreSnapshot snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(fsStore, config, clock)
                    .updateIndex(paths);

            // Assert
            for (OptOutEntry entry : entries) {
                assertEquals(-1L, snapshot.getAdIdOptOutTimestamp(entry.advertisingIdToB64()));
            }
        }

        private List<OptOutEntry> createDelta(int entriesCount, Instant timestamp, MemCachedStorage fsStore) throws CloudStorageException {
            return createDeltaOrPartition(entriesCount, timestamp, fsStore, OptOutUtils.newDeltaFileName(timestamp));
        }

        private List<OptOutEntry> createPartition(int entriesCount, Instant timestamp, MemCachedStorage fsStore) throws CloudStorageException {
            return createDeltaOrPartition(entriesCount, timestamp, fsStore, OptOutUtils.newPartitionFileName(timestamp));
        }

        private List<OptOutEntry> createDeltaOrPartition(int entriesCount, Instant timestamp, MemCachedStorage fsStore, String cloudPath) throws CloudStorageException {
            List<OptOutEntry> entries = createEntries(timestamp, entriesCount);
            fsStore.upload(new ByteArrayInputStream(entriesToByteArray(entries)), cloudPath);
            return entries;
        }

        private List<OptOutEntry> createEntries(Instant timestamp, int count) {
            List<OptOutEntry> entries = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                entries.add(OptOutEntry.newTestEntry(timestamp.plusSeconds(i).toEpochMilli(), timestamp.plusSeconds(i).toEpochMilli()));
            }
            return entries;
        }

        private byte[] entriesToByteArray(List<OptOutEntry> entries) {
            byte[] bytes = new byte[OptOutConst.EntrySize * entries.size()];
            for (int i = 0; i < entries.size(); i++) {
                entries.get(i).copyToByteArray(bytes, OptOutConst.EntrySize * i);
            }
            return bytes;
        }

        private JsonObject make1mOptOutEntryConfig(boolean optOutStatusApiEnabled) {
            final JsonObject config = new JsonObject();
            config.put(Const.Config.OptOutStatusApiEnabled, optOutStatusApiEnabled);
            config.put(Const.Config.OptOutBloomFilterSizeProp, 100000); // 1:10 bloomfilter
            config.put(Const.Config.OptOutHeapDefaultCapacityProp, 1000000); // 1MM record
            config.put("optout_delta_rotate_interval", 86400);
            config.put("optout_partition_interval", 86400);
            config.put("optout_max_partitions", 150);
            return config;
        }
    }
}
