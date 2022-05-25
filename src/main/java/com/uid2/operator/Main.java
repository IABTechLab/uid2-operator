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

package com.uid2.operator;

import com.uid2.operator.monitoring.OperatorMetrics;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import com.uid2.operator.store.*;
import com.uid2.operator.vertx.OperatorDisableHandler;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.ApplicationVersion;
import com.uid2.shared.Utils;
import com.uid2.shared.attest.AttestationFactory;
import com.uid2.shared.attest.UidCoreClient;
import com.uid2.shared.auth.RotatingClientKeyProvider;
import com.uid2.shared.auth.RotatingKeyAclProvider;
import com.uid2.shared.cloud.*;
import com.uid2.shared.jmx.AdminApi;
import com.uid2.shared.optout.OptOutCloudSync;
import com.uid2.shared.store.IMetadataVersionedStore;
import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.vertx.CloudSyncVerticle;
import com.uid2.shared.vertx.ICloudSync;
import com.uid2.shared.vertx.RotatingStoreVerticle;
import com.uid2.shared.vertx.VertxUtils;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.micrometer.prometheus.PrometheusRenameFilter;
import io.vertx.core.*;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.micrometer.Label;
import io.vertx.micrometer.MicrometerMetricsOptions;
import io.vertx.micrometer.VertxPrometheusOptions;
import io.vertx.micrometer.backends.BackendRegistries;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static io.micrometer.core.instrument.Metrics.globalRegistry;

public class Main {
    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    private final JsonObject config;
    private final Vertx vertx;
    private final ApplicationVersion appVersion;
    private final ICloudStorage fsLocal;
    private final ICloudStorage fsOptOut;
    private final ICloudStorage fsStores;

    private final RotatingClientKeyProvider clientKeyProvider;
    private final RotatingKeyStore keyStore;
    private final RotatingKeyAclProvider keyAclProvider;
    private final RotatingSaltProvider saltProvider;
    private final CloudSyncOptOutStore optOutStore;
    private OperatorDisableHandler disableHandler = null;

    private final OperatorMetrics metrics;

    private final AtomicInteger _statsCollectorCount;

    public Main(Vertx vertx, JsonObject config) throws Exception {
        this.vertx = vertx;
        this.config = config;

        this.appVersion = ApplicationVersion.load("uid2-operator", "uid2-shared", "enclave-attestation-api");

        // allow to switch between in-mem optout file cache and on-disk file cache
        if (config.getBoolean(Const.Config.OptOutInMemCacheProp)) {
            this.fsLocal = new MemCachedStorage();
        } else {
            this.fsLocal = new LocalStorageMock();
        }

        boolean useStorageMock = config.getBoolean(Const.Config.StorageMockProp, false);
        String coreAttestUrl = this.config.getString(Const.Config.CoreAttestUrlProp);
        if (coreAttestUrl != null) {
            String coreApiToken = this.config.getString(Const.Config.CoreApiTokenProp);
            UidCoreClient coreClient = createUidCoreClient(coreAttestUrl, coreApiToken);
            this.fsStores = coreClient;
            LOGGER.info("Salt/Key/Client stores - Using uid2-core attestation endpoint: " + coreAttestUrl);

            Duration disableWaitTime = Duration.ofHours(this.config.getInteger(Const.Config.FailureShutdownWaitHoursProp, 120));
            this.disableHandler = new OperatorDisableHandler(disableWaitTime, Clock.systemUTC());
            coreClient.setResponseStatusWatcher(this.disableHandler::handleResponseStatus);

            if (useStorageMock) {
                this.fsOptOut = configureMockOptOutStore();
            } else {
                this.fsOptOut = configureAttestedOptOutStore(coreClient, coreAttestUrl);
            }
        } else if (useStorageMock) {
            this.fsStores = new EmbeddedResourceStorage(Main.class);
            LOGGER.info("Salt/Key/Client stores - Using EmbeddedResourceStorage");

            this.fsOptOut = configureMockOptOutStore();
        } else {
            String coreBucket = this.config.getString(Const.Config.CoreS3BucketProp);
            this.fsStores = CloudUtils.createStorage(coreBucket, config);
            LOGGER.info("Salt/Key/Client stores - Using the same storage as optout: s3://" + coreBucket);

            this.fsOptOut = configureCloudOptOutStore();
        }

        String clientsMdPath = this.config.getString(Const.Config.ClientsMetadataPathProp);
        this.clientKeyProvider = new RotatingClientKeyProvider(this.fsStores, clientsMdPath);
        String keysMdPath = this.config.getString(Const.Config.KeysMetadataPathProp);
        this.keyStore = new RotatingKeyStore(this.fsStores, keysMdPath);
        String keysAclMdPath = this.config.getString(Const.Config.KeysAclMetadataPathProp);
        this.keyAclProvider = new RotatingKeyAclProvider(this.fsStores, keysAclMdPath);
        String saltsMdPath = this.config.getString(Const.Config.SaltsMetadataPathProp);
        this.saltProvider = new RotatingSaltProvider(this.fsStores, saltsMdPath);

        this.optOutStore = new CloudSyncOptOutStore(vertx, fsLocal, this.config);

        if (useStorageMock && coreAttestUrl == null) {
            this.clientKeyProvider.loadContent();
            this.keyStore.loadContent();
            this.keyAclProvider.loadContent();
            this.saltProvider.loadContent();
        }

        metrics = new OperatorMetrics(keyStore, saltProvider);

        _statsCollectorCount = new AtomicInteger(0);
    }

    public static void main(String[] args) throws Exception {
        final String vertxConfigPath = System.getProperty(Const.Config.VERTX_CONFIG_PATH_PROP);
        if (vertxConfigPath != null) {
            System.out.format("Running CUSTOM CONFIG mode, config: %s\n", vertxConfigPath);
        }
        else if (!Utils.isProductionEnvironment()) {
            System.out.format("Running LOCAL DEBUG mode, config: %s\n", Const.Config.LOCAL_CONFIG_PATH);
            System.setProperty(Const.Config.VERTX_CONFIG_PATH_PROP, Const.Config.LOCAL_CONFIG_PATH);
        } else {
            System.out.format("Running PRODUCTION mode, config: %s\n", Const.Config.OVERRIDE_CONFIG_PATH);
        }

        Vertx vertx = createVertx();
        VertxUtils.createConfigRetriever(vertx).getConfig(ar -> {
            if (ar.failed()) {
                LOGGER.fatal("Unable to read config: " + ar.cause().getMessage(), ar.cause());
                return;
            }

            try {
                Main app = new Main(vertx, ar.result());
                app.run();
            } catch (Exception e) {
                LOGGER.fatal("Error: " +e.getMessage(), e);
                vertx.close();
                System.exit(1);
            }
        });
    }

    private ICloudStorage configureMockOptOutStore() {
        // map cloud_mock path to the same directory that local optout produces
        Path cloudMockPath = Paths.get("/opt/uid2/optout/cloud_mock");
        Utils.ensureDirectoryExists(cloudMockPath);
        LOGGER.info("Using LocalStorageMock for optout: " + cloudMockPath.toString());
        return new LocalStorageMock(cloudMockPath.toString());
    }

    private ICloudStorage configureCloudOptOutStore() {
        String optOutBucket = this.config.getString(Const.Config.OptOutS3BucketProp);
        LOGGER.info("Using CloudStorage for optout: s3://" + optOutBucket);
        return this.wrapCloudStorageForOptOut(CloudUtils.createStorage(optOutBucket, config));
    }

    private ICloudStorage configureAttestedOptOutStore(UidCoreClient coreClient, String coreAttestUrl) {
        String optOutMdPath = this.config.getString(Const.Config.OptOutMetadataPathProp);
        LOGGER.info("OptOut stores- Using uid2-core attestation endpoint: " + coreAttestUrl);
        return this.wrapCloudStorageForOptOut(new OptOutCloudStorage(coreClient, optOutMdPath, CloudUtils.defaultProxy));
    }

    private ICloudStorage wrapCloudStorageForOptOut(ICloudStorage cloudStorage) {
        if (config.getBoolean(Const.Config.OptOutS3PathCompatProp)) {
            LOGGER.warn("Using S3 Path Compatibility Conversion: log -> delta, snapshot -> partition");
            return new PathConversionWrapper(
                cloudStorage,
                in -> {
                    String out = in.replace("log", "delta")
                        .replace("snapshot", "partition");
                    LOGGER.debug("S3 path forward convert: " + in + " -> " + out);
                    return out;
                },
                in -> {
                    String out = in.replace("delta", "log")
                        .replace("partition", "snapshot");
                    LOGGER.debug("S3 path backward convert: " + in + " -> " + out);
                    return out;
                }
            );
        } else {
            return cloudStorage;
        }
    }

    private void run() throws Exception {
        Supplier<Verticle> operatorVerticleSupplier = () -> {
            UIDOperatorVerticle verticle = new UIDOperatorVerticle(config, clientKeyProvider, keyStore, keyAclProvider, saltProvider, optOutStore, Clock.systemUTC(), _statsCollectorCount);
            if (this.disableHandler != null)
                verticle.setDisableHandler(this.disableHandler);
            return verticle;
        };

        DeploymentOptions options = new DeploymentOptions();
        int svcInstances = this.config.getInteger(Const.Config.ServiceInstancesProp);
        options.setInstances(svcInstances);

        createStoreVerticles()
            .compose(v -> {
                metrics.setup();
                vertx.setPeriodic(60000, id -> metrics.update());

                Promise<String> promise = Promise.promise();
                vertx.deployVerticle(operatorVerticleSupplier, options, ar -> promise.handle(ar));
                return promise.future();
            })
            .onFailure(t -> {
                LOGGER.fatal("Failed to bootstrap operator: " + t.getMessage(), new Exception(t));
                vertx.close();
                System.exit(1);
            });

        createAndDeployStatsCollector();
    }

    private Future<Void> createStoreVerticles() throws Exception {
        // load metadatas for the first time
        clientKeyProvider.getMetadata();
        keyStore.getMetadata();
        keyAclProvider.getMetadata();
        saltProvider.getMetadata();

        // create cloud sync for optout store
        OptOutCloudSync optOutCloudSync = new OptOutCloudSync(config, false);
        this.optOutStore.registerCloudSync(optOutCloudSync);

        // create rotating store verticles to poll for updates
        Promise<Void> promise = Promise.promise();
        List<Future> fs = new ArrayList<>();
        fs.add(createAndDeployRotatingStoreVerticle("auth", clientKeyProvider, 10000));
        fs.add(createAndDeployRotatingStoreVerticle("key", keyStore, 10000));
        fs.add(createAndDeployRotatingStoreVerticle("keys_acl", keyAclProvider, 10000));
        fs.add(createAndDeployRotatingStoreVerticle("salt", saltProvider, 10000));
        fs.add(createAndDeployCloudSyncStoreVerticle("optout", fsOptOut, optOutCloudSync));
        CompositeFuture.all(fs).onComplete(ar -> {
            if (ar.failed()) promise.fail(new Exception(ar.cause()));
            else promise.complete();
        });
        return promise.future();
    }

    private Future<String> createAndDeployRotatingStoreVerticle(String name, IMetadataVersionedStore store, int intervalMs) {
        Promise<String> promise = Promise.promise();
        RotatingStoreVerticle saltStoreVerticle = new RotatingStoreVerticle(name, intervalMs, store);
        vertx.deployVerticle(saltStoreVerticle, ar -> promise.handle(ar));
        return promise.future();
    }

    private Future<String> createAndDeployCloudSyncStoreVerticle(String name, ICloudStorage fsCloud,
                                                                 ICloudSync cloudSync) {
        Promise<String> promise = Promise.promise();
        CloudSyncVerticle cloudSyncVerticle = new CloudSyncVerticle(name, fsCloud, fsLocal, cloudSync, config);
        vertx.deployVerticle(cloudSyncVerticle, ar -> promise.handle(ar));
        return promise.future()
            .onComplete(v -> setupTimerEvent(cloudSyncVerticle.eventRefresh()));
    }

    private Future<String> createAndDeployStatsCollector() {
        Promise<String> promise = Promise.promise();
        StatsCollectorVerticle statsCollectorVerticle = new StatsCollectorVerticle(60000, this._statsCollectorCount);
        vertx.deployVerticle(statsCollectorVerticle, ar -> promise.handle(ar));
        return promise.future();
    }

    private void setupTimerEvent(String eventCloudRefresh) {
        int cloudRefreshInterval = config.getInteger(Const.Config.CloudRefreshIntervalProp);
        vertx.setPeriodic(1000 * cloudRefreshInterval, id -> {
            LOGGER.trace("emit " + eventCloudRefresh);
            vertx.eventBus().send(eventCloudRefresh, id);
        });
    }

    private static Vertx createVertx() {
        try {
            ObjectName objectName = new ObjectName("uid2.operator:type=jmx,name=AdminApi");
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            server.registerMBean(AdminApi.instance, objectName);
        } catch (InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException e) {
            System.err.format("%s", e.getMessage());
            System.exit(-1);
        }

        final int portOffset = Utils.getPortOffset();
        VertxPrometheusOptions prometheusOptions = new VertxPrometheusOptions()
            .setStartEmbeddedServer(true)
            .setEmbeddedServerOptions(new HttpServerOptions().setPort(Const.Port.PrometheusPortForOperator + portOffset))
            .setEnabled(true);

        MicrometerMetricsOptions metricOptions = new MicrometerMetricsOptions()
            .setPrometheusOptions(prometheusOptions)
            .setLabels(EnumSet.of(Label.HTTP_METHOD, Label.HTTP_CODE, Label.HTTP_PATH))
            .setJvmMetricsEnabled(true)
            .setEnabled(true);
        setupMetrics(metricOptions);

        final int threadBlockedCheckInterval = Utils.isProductionEnvironment()
            ? 60 * 1000
            : 3600 * 1000;

        VertxOptions vertxOptions = new VertxOptions()
            .setMetricsOptions(metricOptions)
            .setBlockedThreadCheckInterval(threadBlockedCheckInterval);

        return Vertx.vertx(vertxOptions);
    }

    private static void setupMetrics(MicrometerMetricsOptions metricOptions) {
        BackendRegistries.setupBackend(metricOptions);

        MeterRegistry backendRegistry = BackendRegistries.getDefaultNow();
        if (backendRegistry instanceof PrometheusMeterRegistry) {
            // prometheus specific configuration
            PrometheusMeterRegistry prometheusRegistry = (PrometheusMeterRegistry) BackendRegistries.getDefaultNow();

            // see also https://micrometer.io/docs/registry/prometheus
            prometheusRegistry.config()
                // providing common renaming for prometheus metric, e.g. "hello.world" to "hello_world"
                .meterFilter(new PrometheusRenameFilter())
                // adding common labels
                .commonTags("application", "uid2-operator");

            // wire my monitoring system to global static state, see also https://micrometer.io/docs/concepts
            Metrics.addRegistry(prometheusRegistry);
        }

        // retrieve image version (will unify when uid2-common is used)
        final String version = Optional.ofNullable(System.getenv("IMAGE_VERSION")).orElse("unknown");
        Gauge
                .builder("app.status", () -> 1)
                .description("application version and status")
                .tags("version", version)
                .register(globalRegistry);
    }

    private UidCoreClient createUidCoreClient(String attestationUrl, String userToken) throws Exception {
        String enclavePlatform = this.config.getString("enclave_platform");
        Boolean enforceHttps = this.config.getBoolean("enforce_https", true);
        if(enclavePlatform != null && enclavePlatform.equals("aws-nitro"))
        {
            LOGGER.info("creating uid core client with aws attestation protocol");
            return new UidCoreClient(attestationUrl, userToken, this.appVersion, CloudUtils.defaultProxy, AttestationFactory.getNitroAttestation(), enforceHttps);
        }
        else if(enclavePlatform != null && enclavePlatform.equals("gcp-vmid"))
        {
            LOGGER.info("creating uid core client with gcp vmid attestation protocol");
            return new UidCoreClient(attestationUrl, userToken, this.appVersion, CloudUtils.defaultProxy, AttestationFactory.getGcpVmidAttestation(), enforceHttps);
        }
        else if(enclavePlatform != null && enclavePlatform.equals("azure-sgx"))
        {
            LOGGER.info("creating uid core client with azure sgx attestation protocol");
            return new UidCoreClient(attestationUrl, userToken, this.appVersion, CloudUtils.defaultProxy, AttestationFactory.getAzureAttestation(), enforceHttps);
        }

        return UidCoreClient.createNoAttest(attestationUrl, userToken, this.appVersion, enforceHttps);
    }
}
