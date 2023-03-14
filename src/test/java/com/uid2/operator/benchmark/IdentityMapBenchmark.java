package com.uid2.operator.benchmark;

import com.uid2.operator.Const;
import com.uid2.operator.Main;
import com.uid2.operator.model.*;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.CloudSyncOptOutStore;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.Utils;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.cloud.InMemoryStorageMock;
import com.uid2.shared.optout.OptOutEntry;
import com.uid2.shared.optout.OptOutHeap;
import com.uid2.shared.optout.OptOutPartition;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.store.reader.RotatingKeyStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class IdentityMapBenchmark {
    private static final IUIDOperatorService uidService;
    private static final UserIdentity[] userIdentities;
    private static int idx = 0;

    static {
        try {
            uidService = createUidOperatorService();
            userIdentities = createUserIdentities();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void IdentityMapRawThroughput() {
        uidService.map(userIdentities[(idx++) & 65535], Instant.now());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void IdentityMapWithOptOutThroughput() {
        uidService.mapIdentity(new MapRequest(userIdentities[(idx++) & 65535], IdentityMapPolicy.RespectOptOut, Instant.now()));
    }

    private static ICloudStorage make1mOptOutEntryStorage(String salt, List<String> out_generatedFiles) throws Exception {
        final InMemoryStorageMock storage = new InMemoryStorageMock();
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final int numEntriesPerPartition = 1000000;
        final int numEntriesToGenerate = 1000000;
        int numPartitionFiles = (numEntriesToGenerate + numEntriesPerPartition - 1) / numEntriesPerPartition;
        int entryId = 0;
        for (int i = 0; i < numPartitionFiles; ++i) {
            OptOutHeap heap = new OptOutHeap(numEntriesPerPartition);

            for (int j = 0; j < numEntriesPerPartition; ++j) {
                String email = String.format("%08d@uidapi.com", entryId++);
                byte[] emailHashBytes = digest.digest(email.getBytes(StandardCharsets.UTF_8));
                String firstLevelId = Utils.toBase64String(emailHashBytes) + salt;
                byte[] firstLevelHashBytes = digest.digest(firstLevelId.getBytes(StandardCharsets.UTF_8));

                OptOutEntry entry = new OptOutEntry(firstLevelHashBytes, firstLevelHashBytes,
                        Instant.now().getEpochSecond());
                heap.add(entry);
            }

            OptOutPartition partition = heap.toPartition(true);
            InputStream data = new ByteArrayInputStream(partition.getStore());
            String fileName = String.format("%s%03d_%s_%08x.dat",
                    "optout-partition-",
                    1,
                    Instant.now().minusSeconds(60)
                                 .truncatedTo(ChronoUnit.DAYS)
                                 .toString()
                                 .replace(':', '.'),
                    i + 1);
            storage.upload(data, fileName);
            out_generatedFiles.add(fileName);
        }

        return storage;
    }

    private static JsonObject make1mOptOutEntryConfig() {
        final JsonObject config = new JsonObject();
        config.put(Const.Config.OptOutBloomFilterSizeProp, 100000); // 1:10 bloomfilter
        config.put(Const.Config.OptOutHeapDefaultCapacityProp, 1000000); // 1MM record
        config.put("optout_delta_rotate_interval", 86400);
        config.put("optout_partition_interval", 86400);
        config.put("optout_max_partitions", 150);
        return config;
    }

    private static IUIDOperatorService createUidOperatorService() throws Exception {
        RotatingKeyStore keyStore = new RotatingKeyStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keys/metadata.json")));
        keyStore.loadContent();

        RotatingSaltProvider saltProvider = new RotatingSaltProvider(
                new EmbeddedResourceStorage(Main.class),
                "/com.uid2.core/test/salts/metadata.json");
        saltProvider.loadContent();

        final int IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = 600;
        final int REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = 900;
        final int REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = 300;

        final JsonObject config = new JsonObject();
        config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);

        final EncryptedTokenEncoder tokenEncoder = new EncryptedTokenEncoder(keyStore);
        final List<String> optOutPartitionFiles = new ArrayList<>();
        final ICloudStorage optOutLocalStorage = make1mOptOutEntryStorage(
                saltProvider.getSnapshot(Instant.now()).getFirstLevelSalt(),
                /* out */ optOutPartitionFiles);
        final IOptOutStore optOutStore = new StaticOptOutStore(optOutLocalStorage, make1mOptOutEntryConfig(), optOutPartitionFiles);

        return new UIDOperatorService(
                config,
                optOutStore,
                saltProvider,
                tokenEncoder,
                Clock.systemUTC(),
                IdentityScope.UID2
        );
    }

    private static UserIdentity[] createUserIdentities() {
        UserIdentity[] arr = new UserIdentity[65536];
        for (int i = 0; i < 65536; i++) {
            final byte[] id = new byte[33];
            new Random().nextBytes(id);
            arr[i] = new UserIdentity(IdentityScope.UID2, IdentityType.Email, id, 0,
                    Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
        }
        return arr;
    }

    private static class StaticOptOutStore implements IOptOutStore {
        private CloudSyncOptOutStore.OptOutStoreSnapshot snapshot;

        public StaticOptOutStore(ICloudStorage storage, JsonObject jsonConfig, Collection<String> partitions) throws CloudStorageException, IOException {
            snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(storage, jsonConfig);
            snapshot = snapshot.updateIndex(partitions);
            System.out.println(snapshot.size());
        }

        @Override
        public Instant getLatestEntry(UserIdentity firstLevelHashIdentity) {
            long epochSecond = this.snapshot.getOptOutTimestamp(firstLevelHashIdentity.id);
            Instant instant = epochSecond > 0 ? Instant.ofEpochSecond(epochSecond) : null;
            return instant;
        }

        @Override
        public void addEntry(UserIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler) {
            // noop
        }
    }
}
