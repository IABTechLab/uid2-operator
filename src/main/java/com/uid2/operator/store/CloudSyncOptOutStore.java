package com.uid2.operator.store;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.Const;
import com.uid2.operator.model.UserIdentity;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.shared.Utils;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.cloud.MemCachedStorage;
import com.uid2.shared.optout.*;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.codec.BodyCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.stream.Collectors;

public class CloudSyncOptOutStore implements IOptOutStore {
    private static final Logger LOGGER = LoggerFactory.getLogger(CloudSyncOptOutStore.class);

    private final AtomicReference<OptOutStoreSnapshot> snapshot = new AtomicReference<>(null);
    private final ICloudStorage fsLocal;
    private final WebClient webClient;
    private final int remoteApiPort;
    private final String remoteApiHost;
    private final String remoteApiPath;
    private final String remoteApiBearerToken;

    public CloudSyncOptOutStore(Vertx vertx, ICloudStorage fsLocal, JsonObject jsonConfig, String operatorKey, Clock clock) throws MalformedURLException {
        this.fsLocal = fsLocal;
        this.webClient = WebClient.create(vertx);

        String remoteApi = jsonConfig.getString(Const.Config.OptOutApiUriProp);
        if (remoteApi != null) {
            URL url = new URL(remoteApi);
            this.remoteApiPort = -1 == url.getPort() ? 80 : url.getPort();
            this.remoteApiHost = url.getHost();
            this.remoteApiPath = url.getPath();
            this.remoteApiBearerToken = "Bearer " + operatorKey;
        } else {
            this.remoteApiPort = -1;
            this.remoteApiHost = null;
            this.remoteApiPath = null;
            this.remoteApiBearerToken = null;
        }

        this.snapshot.set(new OptOutStoreSnapshot(fsLocal, jsonConfig, clock));
    }

    @Override
    public Instant getLatestEntry(UserIdentity firstLevelHashIdentity) {
        long epochSecond = this.snapshot.get().getOptOutTimestamp(firstLevelHashIdentity.id);
        Instant instant = epochSecond > 0 ? Instant.ofEpochSecond(epochSecond) : null;
        return instant;
    }

    @Override
    public long getOptOutTimestampByAdId(String adId) {
        return this.snapshot.get().getAdIdOptOutTimestamp(adId);
    }

    @Override
    public void addEntry(UserIdentity firstLevelHashIdentity, byte[] advertisingId, Handler<AsyncResult<Instant>> handler) {
        if (remoteApiHost == null) {
            handler.handle(Future.failedFuture("remote api not set"));
            return;
        }

        this.webClient.get(remoteApiPort, remoteApiHost, remoteApiPath).
            addQueryParam("identity_hash", EncodingUtils.toBase64String(firstLevelHashIdentity.id))
            .addQueryParam("advertising_id", EncodingUtils.toBase64String(advertisingId))
            .putHeader("Authorization", remoteApiBearerToken)
            .as(BodyCodec.string())
            .send(ar -> {
                Exception failure = null;
                if (ar.failed()) {
                    failure = new Exception(ar.cause());
                } else if (ar.result().statusCode() != 200) {
                    failure = new Exception("optout api http status: " + String.valueOf(ar.result().statusCode()));
                }

                if (failure == null) {
                    handler.handle(Future.succeededFuture(Utils.nowUTCMillis()));
                } else {
                    LOGGER.error("CloudSyncOptOutStore.addEntry remote web request failed", failure);
                    handler.handle(Future.failedFuture(failure));
                }
            });
    }

    public void registerCloudSync(OptOutCloudSync cloudSync) {
        cloudSync.registerNewCachedPathsHandler(cp -> this.handleNewCachedPaths(cp));
    }

    private void handleNewCachedPaths(Collection<String> cachedPaths) {
        try {
            OptOutStoreSnapshot oldSnapshot = this.snapshot.get();
            long oldEntries = oldSnapshot.size();
            OptOutStoreSnapshot newSnapshot = this.snapshot.get().updateIndex(cachedPaths);
            this.snapshot.set(newSnapshot);
            long newentries = newSnapshot.size();

            if (oldEntries != newentries) {
                LOGGER.info("OptOutStore refreshed with " + newentries + " entries");
            }
        } catch (Exception e) {
            LOGGER.error("update index error: " + e.getMessage(), e);
        }
    }

    private void remoteGetLatestEntry(String key, Handler<AsyncResult<Instant>> handler) {
        this.webClient.get(8081, "localhost", "/optout/get").
            addQueryParam("email_hash", key)
            .as(BodyCodec.string())
            .send(ar -> {
                if (ar.succeeded()) {
                    final HttpResponse<String> response = ar.result();
                    final String body = response.body();
                    final long value;
                    try {
                        value = Long.parseLong(body);
                    } catch (Exception e) {
                        handler.handle(Future.failedFuture(e));
                        return;
                    }
                    final Instant instant;
                    if (value <= 0) {
                        instant = null;
                    } else {
                        instant = Instant.ofEpochSecond(value);
                    }
                    handler.handle(Future.succeededFuture(instant));
                } else {
                    if (ar.cause() != null) {
                        LOGGER.error("remoteGetLatestEntry error", ar.cause());
                    }
                    handler.handle(Future.failedFuture(ar.cause()));

                }
            });
    }

    public static class IndexUpdateMessage {
        public static IndexUpdateMessage EMPTY = new IndexUpdateMessage();
        private static ObjectMapper mapper = new ObjectMapper();

        @JsonProperty("partitionsToAdd")
        protected List<String> partitionsToAdd = new ArrayList<>();

        @JsonProperty("deltasToAdd")
        protected List<String> deltasToAdd = new ArrayList<>();

        @JsonProperty("deltasToRemove")
        protected List<String> deltasToRemove = new ArrayList<>();

        public static IndexUpdateMessage fromJsonString(String str) {
            try {
                return IndexUpdateMessage.mapper.readValue(str, IndexUpdateMessage.class);
            } catch (JsonProcessingException ex) {
                // IndexUpdateMessage is an internal message, any serialization and deserialization exception is logic error
                // return null here
                return null;
            }
        }

        public String toJsonString() {
            try {
                return IndexUpdateMessage.mapper.writeValueAsString(this);
            } catch (JsonProcessingException ex) {
                // IndexUpdateMessage is an internal message, any serialization and deserialization exception is logic error
                // return null here
                return null;
            }
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof IndexUpdateMessage)) {
                return false;
            }
            IndexUpdateMessage m = (IndexUpdateMessage) o;
            return Objects.equals(partitionsToAdd, m.partitionsToAdd) &&
                Objects.equals(deltasToAdd, m.deltasToAdd) &&
                Objects.equals(deltasToRemove, m.deltasToRemove);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.partitionsToAdd, this.deltasToAdd, this.deltasToRemove);
        }

        public void reset() {
            this.deltasToAdd.clear();
            this.partitionsToAdd.clear();
            this.deltasToRemove.clear();
        }

        public void addPartitionFile(String file) {
            this.partitionsToAdd.add(file);
        }

        public void addDeltaFile(String file) {
            this.deltasToAdd.add(file);
        }

        public void removeDeltaFile(String file) {
            this.deltasToRemove.add(file);
        }

        public List<String> getPartitionsToAdd() {
            return this.partitionsToAdd;
        }

        public List<String> getDeltasToAdd() {
            return this.deltasToAdd;
        }

        public List<String> getDeltasToRemove() {
            return this.deltasToRemove;
        }

        public Instant lastTimestamp() {
            List<Instant> ts = new ArrayList<>();
            ts.addAll(this.deltasToAdd.stream().map(f -> OptOutUtils.getFileTimestamp(f)).collect(Collectors.toList()));
            ts.addAll(this.partitionsToAdd.stream().map(f -> OptOutUtils.getFileTimestamp(f)).collect(Collectors.toList()));
            if (ts.size() == 0) return Instant.EPOCH;
            return ts.stream().max(Instant::compareTo).get();
        }
    }

    public static class IndexUpdateContext extends IndexUpdateMessage {

        private HashMap<String, byte[]> loadedPartitions = new HashMap<>();
        private HashMap<String, byte[]> loadedDeltas = new HashMap<>();

        private IndexUpdateContext(IndexUpdateMessage ium) {
            this.deltasToAdd = ium.getDeltasToAdd();
            this.partitionsToAdd = ium.getPartitionsToAdd();
            this.deltasToRemove = ium.getDeltasToRemove();
        }

        public static IndexUpdateContext fromMessage(IndexUpdateMessage ium) {
            return new IndexUpdateContext(ium);
        }

        public IndexUpdateMessage result() {
            // return a message with loaded files
            IndexUpdateMessage ium = new IndexUpdateMessage();
            ium.getDeltasToAdd().addAll(this.loadedDeltas.keySet());
            ium.getPartitionsToAdd().addAll(this.loadedPartitions.keySet());
            return ium;
        }

        public void addLoadedDelta(String f, byte[] data) {
            this.loadedDeltas.put(f, data);
        }

        public void addLoadedPartition(String f, byte[] data) {
            this.loadedPartitions.put(f, data);
        }

        public Collection<byte[]> getLoadedDeltas() {
            return this.loadedDeltas.values();
        }

        public Collection<byte[]> getLoadedPartitions() {
            return this.loadedPartitions.values();
        }
    }

    public static class OptOutStoreSnapshot {
        private static final Logger LOGGER = LoggerFactory.getLogger(OptOutStoreSnapshot.class);

        private static final Gauge gaugeEntriesIndexed = Gauge
            .builder("uid2.optout.entries_indexed", () -> OptOutStoreSnapshot.totalEntries.get())
            .description("gauge for how many optout entries are indexed")
            .register(Metrics.globalRegistry);

        private static final Counter counterDeltasIndexed = Counter
            .builder("uid2.optout.deltas_indexed")
            .description("counter for how many optout delta files are indexed")
            .register(Metrics.globalRegistry);

        private static final Counter counterPartitionsIndexed = Counter
            .builder("uid2.optout.partitions_indexed")
            .description("counter for how many optout parition files are indexed")
            .register(Metrics.globalRegistry);

        private static final Counter counterIndexUpdated = Counter
            .builder("uid2.optout.index_updated")
            .description("counter for how many times index is updated")
            .register(Metrics.globalRegistry);

        private static final Gauge gaugeBloomfilterSize = Gauge
            .builder("uid2.optout.bloomfilter_size", () -> OptOutStoreSnapshot.bloomFilterSize.get())
            .description("gauge for number of entries cached in bloomfilter")
            .register(Metrics.globalRegistry);

        private static final Gauge gaugeBloomfilterMax = Gauge
            .builder("uid2.optout.bloomfilter_max", () -> OptOutStoreSnapshot.bloomFilterMax.get())
            .description("gauge for max entries can be cached in bloomfilter")
            .register(Metrics.globalRegistry);

        // stores the timestamp of last updated delta or partition file
        private static final AtomicReference<Instant> lastUpdatedTimestamp = new AtomicReference<>(Instant.EPOCH);
        private static final AtomicLong bloomFilterSize = new AtomicLong(0);
        private static final AtomicLong bloomFilterMax = new AtomicLong(0);
        private static final AtomicLong totalEntries = new AtomicLong(0);
        private static final BiFunction<Long, Long, Long> OPT_OUT_TIMESTAMP_MERGE_STRATEGY = Long::min;

        private final DownloadCloudStorage fsLocal;

        // holds a heap data structure for unsorted optout entries
        // a new optout log will be produced at a regular interval (5mins), which will be loaded to heap
        private final OptOutHeap heap;

        // a bloom filter to help optimizing the non-existing case for optout entry lookup
        private final BloomFilter bloomFilter;


        /**
         * A map from advertising IDs to optout timestamps.
         */
        private final Map<String, Long> adIdToOptOutTimestamp;

        private final boolean optoutStatusApiEnabled;

        // array of optout partitions
        private final OptOutPartition[] partitions;

        // Index iteration, a counter that increases by 1 for every index.update event
        private final int iteration;

        private final Set<String> indexedFiles;

        private final FileUtils fileUtils;

        private final Clock clock;

        public OptOutStoreSnapshot(DownloadCloudStorage fsLocal, JsonObject jsonConfig, Clock clock) {
            this.clock = clock;
            this.fsLocal = fsLocal;
            this.fileUtils = new FileUtils(jsonConfig);

            // initially iteration 0
            this.iteration = 0;

            // create bloom filter
            int bloomFilterSize = jsonConfig.getInteger(Const.Config.OptOutBloomFilterSizeProp);
            this.bloomFilter = new BloomFilter(bloomFilterSize);

            // create heap
            int heapCapacity = jsonConfig.getInteger(Const.Config.OptOutHeapDefaultCapacityProp);
            this.heap = new OptOutHeap(heapCapacity);

            this.adIdToOptOutTimestamp = Collections.emptyMap();
            this.optoutStatusApiEnabled = jsonConfig.getBoolean(Const.Config.OptOutStatusApiEnabled, false);

            // initially 1 partition
            this.partitions = new OptOutPartition[1];
            // First partition intentionally null.
            // Calling toPartition on an empty heap causes an assertion failure.

            // initially no indexed files
            this.indexedFiles = Collections.emptySet();
        }

        public OptOutStoreSnapshot(OptOutStoreSnapshot last, BloomFilter bf, OptOutHeap heap,
                                   OptOutPartition[] newPartitions, IndexUpdateContext iuc,
                                   boolean optoutStatusApiEnabled) {
            this.clock = last.clock;
            this.fsLocal = last.fsLocal;
            this.fileUtils = last.fileUtils;
            this.iteration = last.iteration + 1;

            this.bloomFilter = bf;
            this.heap = heap;
            this.partitions = newPartitions;

            Set<String> newIndexedFiles = new HashSet<>(last.indexedFiles);
            newIndexedFiles.removeAll(iuc.deltasToRemove);
            newIndexedFiles.addAll(iuc.loadedDeltas.keySet());
            newIndexedFiles.addAll(iuc.loadedPartitions.keySet());
            this.indexedFiles = Collections.unmodifiableSet(newIndexedFiles);

            this.optoutStatusApiEnabled = optoutStatusApiEnabled;
            if (this.optoutStatusApiEnabled) {
                HashMap<String, Long> newOptOutTimestamps = new HashMap<>();
                for (OptOutPartition partition : this.partitions) {
                    if (partition == null) continue;
                    partition.forEach(entry -> {
                        newOptOutTimestamps.merge(entry.advertisingIdToB64(), entry.timestamp, OPT_OUT_TIMESTAMP_MERGE_STRATEGY);
                    });
                }
                this.adIdToOptOutTimestamp = Collections.unmodifiableMap(newOptOutTimestamps);
            } else {
                this.adIdToOptOutTimestamp = Collections.emptyMap();
            }

            // update total entries
            totalEntries.set(size());
        }

        public long size() {
            return Arrays.stream(this.partitions)
                .filter(Objects::nonNull)
                .mapToLong(OptOutPartition::size)
                .sum();
        }

        // method provided for OptOutService to assess health
        public boolean isHealthy(Instant now) {
            // index is healthy if it is updated within 3 * logRotationInterval
            return lastUpdatedTimestamp.get().plusSeconds(fileUtils.lookbackGracePeriod()).isAfter(now);
        }

        public long getAdIdOptOutTimestamp(String advertisingId) {
            return this.adIdToOptOutTimestamp.getOrDefault(advertisingId, -1L);
        }

        // method provided for OptOutService to call
        public long getOptOutTimestamp(byte[] hashBytes) {
            // null hash is a special case, we will return now() epoch seconds for null hash
            if (Arrays.equals(hashBytes, OptOutUtils.nullHashBytes)) return OptOutUtils.nowEpochSeconds();
            // ones hash is a special case, we will always return -1 for ones hash (0xff...ff)
            if (Arrays.equals(hashBytes, OptOutUtils.onesHashBytes)) return -1;

            if (!this.bloomFilter.likelyContains(hashBytes)) {
                // bloom filter says no, which would be final
                return -1;
            }

            for (OptOutPartition s : this.partitions) {
                if (s == null) continue;
                long ts = s.getOptOutTimestamp(hashBytes);
                if (ts != -1) return ts;
            }

            // not found any where, return not found
            return -1;
        }

        public OptOutStoreSnapshot updateIndex(Collection<String> cachedPath) throws IOException, CloudStorageException {
            IndexUpdateMessage ium = this.getIndexUpdateMessage(clock.instant(), cachedPath);
            return this.updateIndex(ium);
        }

        private IndexUpdateMessage getIndexUpdateMessage(Instant now, Collection<String> cachedPaths) {
            // return EMPTY message if there are no cached s3 files
            if (cachedPaths.size() == 0) return IndexUpdateMessage.EMPTY;

            // find not expired and not indexed files
            IndexUpdateMessage ium = new IndexUpdateMessage();
            HashSet<String> notIndexed = new HashSet<>(cachedPaths);
            notIndexed.removeAll(indexedFiles);

            // filter out delta that are already merged into partition files
            List<String> fileList = filterIndexUpdateFiles(notIndexed, now);
            for (String f : fileList) {
                if (OptOutUtils.isDeltaFile(f))
                    ium.addDeltaFile(f);
                else if (OptOutUtils.isPartitionFile(f))
                    ium.addPartitionFile(f);
                else assert false;
            }

            Collection<String> indexedNonSynthetic = indexedFiles.stream()
                .filter(f -> !OptOutUtils.isSyntheticFile(f))
                .collect(Collectors.toList());

            Collection<String> newNonSynthetic = fileList.stream()
                .filter(f -> !OptOutUtils.isSyntheticFile(f))
                .collect(Collectors.toList());

            Instant tsOld = OptOutUtils.lastPartitionTimestamp(indexedNonSynthetic);
            Instant tsNew = OptOutUtils.lastPartitionTimestamp(newNonSynthetic);
            assert tsOld == Instant.EPOCH || tsNew == Instant.EPOCH || tsOld.isBefore(tsNew);
            // if there are new partitions in this update, let index delete some in-mem delta caches that is old
            if (tsNew != Instant.EPOCH) {
                tsNew = tsNew.minusSeconds(fileUtils.lookbackGracePeriod());
                List<String> toRemove = fileUtils.filterFileInRange(indexedNonSynthetic, tsOld, tsNew);
                for (String f : toRemove) {
                    ium.removeDeltaFile(f);
                }
            }

            return ium;
        }

        private OptOutStoreSnapshot updateIndex(IndexUpdateMessage ium) throws IOException, CloudStorageException {
            // noop for EMPTY message
            if (ium.equals(IndexUpdateMessage.EMPTY)) {
                // empty index update message also updates last updated timestamp
                this.updateIndexTimestamp(clock.instant());

                // empty message won't increase iteration counter
                return this;
            }

            IndexUpdateContext iuc = IndexUpdateContext.fromMessage(ium);

            // load all partition files
            for (String filePath : ium.getPartitionsToAdd()) {
                LOGGER.info("Reading optout partition file : " + filePath);
                byte[] data = this.loadFile(filePath);
                if (data.length == 0) {
                    LOGGER.warn("OptOut partition file is empty: " + filePath);
                    continue;
                }
                iuc.addLoadedPartition(filePath, data);
            }

            // load all log files
            List<String> addDeltaFiles = ium.getDeltasToAdd();
            for (String filePath : addDeltaFiles) {
                LOGGER.trace("Reading optout delta file : " + filePath);
                byte[] data = loadFile(filePath);
                if (data.length == 0) {
                    LOGGER.warn("OptOut delta file is empty: " + filePath);
                    continue;
                }
                iuc.addLoadedDelta(filePath, data);
            }

            return this.updateIndexInternal(iuc);
        }

        private OptOutStoreSnapshot updateIndexInternal(IndexUpdateContext iuc) {
            int numPartitions = iuc.getLoadedPartitions().size();
            try {
                if (numPartitions == 0) {
                    // if update doesn't have a new partition, simply update heap with new log data
                    assert iuc.getDeltasToRemove().size() == 0;
                    return this.processDeltas(iuc);
                } else if (numPartitions > 1) {
                    // should not load more than 1 partition at a time, unless during service bootstrap
                    assert this.iteration == 0;
                    return this.processPartitions(iuc);
                } else {
                    // array size cannot be a negative value
                    assert numPartitions == 1;
                    return this.processPartitions(iuc);
                }
            } finally {
                // Update index update timestamp from the result
                IndexUpdateMessage result = iuc.result();
                this.updateIndexTimestamp(result.lastTimestamp());

                this.counterPartitionsIndexed.increment(numPartitions);
                this.counterDeltasIndexed.increment(result.getDeltasToAdd().size());
                this.counterIndexUpdated.increment();
            }
        }

        private OptOutStoreSnapshot processDeltas(IndexUpdateContext iuc) {
            Collection<byte[]> loadedData = iuc.getLoadedDeltas();
            if (loadedData.size() == 0) return this;

            // in-place updating heap and bloomfilter
            // this is thread-safe, as heap is not being used
            // and bloomfilter can tolerate false positive
            for (byte[] data : loadedData) {
                assert data.length != 0;

                OptOutCollection newLog = new OptOutCollection(data);
                this.heap.add(newLog);

                // set new entries found in the log file in bloomfilter
                newLog.set(this.bloomFilter);
            }

            // create a copy array, and replace the 1st entry
            OptOutPartition[] newPartitions = Arrays.copyOf(this.partitions, this.partitions.length);
            // Calling toPartition on an empty heap causes an assertion failure.
            newPartitions[0] = this.heap.isEmpty() ? null : this.heap.toPartition(true);

            OptOutStoreSnapshot.bloomFilterSize.set(this.bloomFilter.size());
            return new OptOutStoreSnapshot(this, this.bloomFilter, this.heap, newPartitions, iuc, this.optoutStatusApiEnabled);
        }

        private OptOutStoreSnapshot processPartitions(IndexUpdateContext iuc) {
            int newSnaps = iuc.getLoadedPartitions().size();
            if (newSnaps == 0) return this;

            int totalSnaps = this.partitions.length + newSnaps;
            OptOutPartition[] newPartitions = new OptOutPartition[totalSnaps];

            // reset and rebuild heap, with recent files after every partition load
            // OptOutHeap newHeap = new OptOutHeap(this.heap.capacity());
            // TODO: improve delta loading
            OptOutHeap newHeap = this.heap.clone();
            for (byte[] data : iuc.getLoadedDeltas()) {
                newHeap.add(new OptOutCollection(data));
            }

            // produce a in-mem sorted partition for entries in heap
            // Calling toPartition on an empty heap causes an assertion failure.
            newPartitions[0] = newHeap.isEmpty() ? null : newHeap.toPartition(true);

            // the order of partition files needs to be sorted in time descending order
            int snapIndex = 1;
            Collection<String> sortedPartitionFiles = iuc.loadedPartitions.keySet();
            if (sortedPartitionFiles.size() > 1) {
                sortedPartitionFiles = sortedPartitionFiles.stream()
                    .sorted(OptOutUtils.DeltaFilenameComparatorDescending)
                    .collect(Collectors.toList());
            }
            for (String key : sortedPartitionFiles) {
                byte[] data = iuc.loadedPartitions.get(key);
                assert data.length != 0;
                newPartitions[snapIndex++] = new OptOutPartition(data);
            }

            // copy the old partition files, starting from index 1
            for (int i = snapIndex; i < totalSnaps; ++i) {
                newPartitions[i] = this.partitions[1 + i - snapIndex];
            }

            // create a new bloomfilter, since adding new partition can retire old ones
            BloomFilter newBf = this.newBloomFilter(newPartitions);
            for (int i = 0; i < newPartitions.length; ++i) {
                if (newPartitions[i] == null) continue;
                newPartitions[i].set(newBf);
            }

            OptOutStoreSnapshot.bloomFilterSize.set(newBf.size());
            OptOutStoreSnapshot.bloomFilterMax.set(newBf.capacity());
            return new OptOutStoreSnapshot(this, newBf, newHeap, newPartitions, iuc, this.optoutStatusApiEnabled);
        }

        // used for finding files to feed to index
        private List<String> filterIndexUpdateFiles(Collection<String> collection, Instant now) {
            List<String> files = new ArrayList<>();

            // find only 1 partition per partition interval, e.g. if set to 86400s, find 1 (the first) partition per day
            Map<Instant, String> snapByDay = collection.stream()
                .filter(f -> OptOutUtils.isPartitionFile(f) && !OptOutUtils.isSyntheticFile(f))
                .collect(Collectors.toMap(
                    f -> fileUtils.truncateToPartitionCutoffTime(OptOutUtils.getFileTimestamp(f)),
                    Function.identity(),
                    BinaryOperator.minBy(Comparator.comparing(OptOutUtils::getFileEpochSeconds))
                ));
            snapByDay.forEach((day, f) -> files.add(f));

            // find the timestamp of the last partition file
            Instant tsOfLastSnap = OptOutUtils.lastPartitionTimestamp(files);
            if (tsOfLastSnap != Instant.EPOCH) {
                // allow delta files with some gap before the last snap time to be loaded
                tsOfLastSnap = tsOfLastSnap.minusSeconds(fileUtils.lookbackGracePeriod());
            }

            // add the delta files after the last partition
            final Instant tsOfSnap = tsOfLastSnap;
            files.addAll(collection.stream()
                .filter(f -> OptOutUtils.isDeltaFile(f) && !OptOutUtils.isDeltaBeforePartition(tsOfSnap, f))
                .collect(Collectors.toList()));

            // add synthetic files
            files.addAll(collection.stream()
                .filter(f -> OptOutUtils.isSyntheticFile(f))
                .collect(Collectors.toList()));

            // duplicates detection
            Set<String> filesSet = new HashSet<>(files);
            if (filesSet.size() != files.size()) {
                LOGGER.error("There are " + (files.size() - filesSet.size()) + " duplicates in the update");
            }

            return files;
        }

        private void updateIndexTimestamp(Instant ts) {
            if (this.lastUpdatedTimestamp.get().isBefore(ts)) {
                this.lastUpdatedTimestamp.set(ts);
            }
        }

        private BloomFilter newBloomFilter(OptOutPartition[] newPartitions) {
            long newSize = Arrays.stream(newPartitions)
                .filter(Objects::nonNull)
                .mapToLong(OptOutPartition::size)
                .sum();

            BloomFilter bf = this.bloomFilter;
            if (bf.capacity() < newSize || bf.load() > 0.1) {
                // allocate new bloomfilter with ideal capacity
                BloomFilter newBf = new BloomFilter(BloomFilter.idealCapacity(newSize));

                LOGGER.info("Bloomfilter potentially overloaded, size = " + bf.size()
                    + ", capacity = " + bf.capacity()
                    + ", new_size = " + newSize
                    + ", new_capacity = " + newBf.capacity());
                bf = newBf;
            } else {
                bf = new BloomFilter(bf.capacity());
            }
            return bf;
        }

        private byte[] loadFile(String filePath) throws CloudStorageException, IOException {
            if (fsLocal instanceof MemCachedStorage) {
                // read the byte[] directly to skip double buffering
                return ((MemCachedStorage)fsLocal).getBytes(filePath);
            } else {
                try (InputStream inputStream = fsLocal.download(filePath)) {
                    return Utils.streamToByteArray(inputStream);
                }
            }
        }
    }
}
