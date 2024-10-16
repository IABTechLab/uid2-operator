package com.uid2.operator.benchmark;

import com.uid2.operator.Const;
import com.uid2.operator.Main;
import com.uid2.operator.model.*;
import com.uid2.operator.model.userIdentity.FirstLevelHashIdentity;
import com.uid2.operator.model.userIdentity.HashedDiiIdentity;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.CloudSyncOptOutStore;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.cloud.InMemoryStorageMock;
import com.uid2.shared.optout.OptOutEntry;
import com.uid2.shared.optout.OptOutHeap;
import com.uid2.shared.optout.OptOutPartition;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.store.reader.RotatingClientKeyProvider;
import com.uid2.shared.store.reader.RotatingKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

public class BenchmarkCommon {

     static IUIDOperatorService createUidOperatorService() throws Exception {
        RotatingKeysetKeyStore keysetKeyStore = new RotatingKeysetKeyStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keyset_keys/metadata.json")));
        keysetKeyStore.loadContent();

         RotatingKeysetProvider keysetProvider = new RotatingKeysetProvider(
                 new EmbeddedResourceStorage(Main.class),
                 new GlobalScope(new CloudPath("/com.uid2.core/test/keysets/metadata.json")));
         keysetProvider.loadContent();

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

        final EncryptedTokenEncoder tokenEncoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
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
                IdentityScope.UID2,
                null
        );
    }

    static EncryptedTokenEncoder createTokenEncoder() throws Exception {
        RotatingKeysetKeyStore keysetKeyStore = new RotatingKeysetKeyStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keyset_keys/metadata.json")));
        keysetKeyStore.loadContent();

        RotatingKeysetProvider keysetProvider = new RotatingKeysetProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keysets/metadata.json")));
        keysetKeyStore.loadContent();

        return new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
    }

    static JsonObject make1mOptOutEntryConfig() {
        final JsonObject config = new JsonObject();
        config.put(Const.Config.OptOutBloomFilterSizeProp, 100000); // 1:10 bloomfilter
        config.put(Const.Config.OptOutHeapDefaultCapacityProp, 1000000); // 1MM record
        config.put("optout_delta_rotate_interval", 86400);
        config.put("optout_partition_interval", 86400);
        config.put("optout_max_partitions", 150);
        return config;
    }

    static ICloudStorage make1mOptOutEntryStorage(String salt, List<String> out_generatedFiles) throws Exception {
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

    static HashedDiiIdentity[] createHashedDiiIdentities() {
        HashedDiiIdentity[] arr = new HashedDiiIdentity[65536];
        for (int i = 0; i < 65536; i++) {
            final byte[] diiHash = new byte[33];
            new Random().nextBytes(diiHash);
            arr[i] = new HashedDiiIdentity(IdentityScope.UID2, IdentityType.Email, diiHash, 0,
                    Instant.now().minusSeconds(120));
        }
        return arr;
    }

    static SourcePublisher createSourcePublisher() throws Exception {
        RotatingClientKeyProvider clients = new RotatingClientKeyProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/clients/metadata.json")));
        clients.loadContent();

        for (ClientKey client : clients.getAll()) {
            if (client.hasRole(Role.GENERATOR)) {
                return new SourcePublisher(client.getSiteId(), 0, 0);
            }
        }
        throw new IllegalStateException("embedded resource does not include any publisher key");
    }


    /**
     * In memory optout store. Initialize with everything. Does not support modification
     */
    static class StaticOptOutStore implements IOptOutStore {
        private CloudSyncOptOutStore.OptOutStoreSnapshot snapshot;

        public StaticOptOutStore(ICloudStorage storage, JsonObject jsonConfig, Collection<String> partitions) throws CloudStorageException, IOException {
            snapshot = new CloudSyncOptOutStore.OptOutStoreSnapshot(storage, jsonConfig, Clock.systemUTC());
            snapshot = snapshot.updateIndex(partitions);
            System.out.println(snapshot.size());
        }

        @Override
        public Instant getLatestEntry(FirstLevelHashIdentity firstLevelHashIdentity) {
            long epochSecond = this.snapshot.getOptOutTimestamp(firstLevelHashIdentity.firstLevelHash);
            Instant instant = epochSecond > 0 ? Instant.ofEpochSecond(epochSecond) : null;
            return instant;
        }

        @Override
        public void addEntry(FirstLevelHashIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler) {
            // noop
        }

        @Override
        public long getOptOutTimestampByAdId(String adId) {
            return -1;
        }
    }

}
