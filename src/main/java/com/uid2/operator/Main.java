package com.uid2.operator;

import ch.qos.logback.classic.LoggerContext;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.OperatorMetrics;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import com.uid2.operator.store.*;
import com.uid2.operator.vertx.OperatorDisableHandler;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.ApplicationVersion;
import com.uid2.shared.Utils;
import com.uid2.shared.attest.AttestationFactory;
import com.uid2.shared.attest.AttestationTokenRetriever;
import com.uid2.shared.attest.NoAttestationProvider;
import com.uid2.shared.attest.UidCoreClient;
import com.uid2.shared.cloud.*;
import com.uid2.shared.jmx.AdminApi;
import com.uid2.shared.optout.OptOutCloudSync;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import com.uid2.shared.store.reader.RotatingClientKeyProvider;
import com.uid2.shared.store.reader.RotatingKeyAclProvider;
import com.uid2.shared.store.reader.RotatingKeyStore;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.vertx.CloudSyncVerticle;
import com.uid2.shared.vertx.ICloudSync;
import com.uid2.shared.vertx.RotatingStoreVerticle;
import com.uid2.shared.vertx.VertxUtils;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.micrometer.prometheus.PrometheusRenameFilter;
import io.vertx.core.*;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.impl.HttpUtils;
import io.vertx.core.json.JsonObject;
import io.vertx.micrometer.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.vertx.micrometer.backends.BackendRegistries;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.function.Supplier;

import static io.micrometer.core.instrument.Metrics.globalRegistry;

public class Main {
    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    private final JsonObject config;
    private final Vertx vertx;
    private final ApplicationVersion appVersion;
    private final ICloudStorage fsLocal;
    private final ICloudStorage fsOptOut;

    private final RotatingClientKeyProvider clientKeyProvider;
    private final RotatingKeyStore keyStore;
    private final RotatingKeyAclProvider keyAclProvider;
    private final RotatingSaltProvider saltProvider;
    private final CloudSyncOptOutStore optOutStore;
    private OperatorDisableHandler disableHandler = null;

    private final OperatorMetrics metrics;

    private IStatsCollectorQueue _statsCollectorQueue;

    public Main(Vertx vertx, JsonObject config) throws Exception {
        this.vertx = vertx;
        this.config = config;

        this.appVersion = ApplicationVersion.load("uid2-operator", "uid2-shared", "uid2-attestation-api");

        // allow to switch between in-mem optout file cache and on-disk file cache
        if (config.getBoolean(Const.Config.OptOutInMemCacheProp)) {
            this.fsLocal = new MemCachedStorage();
        } else {
            this.fsLocal = new LocalStorageMock();
        }

        boolean useStorageMock = config.getBoolean(Const.Config.StorageMockProp, false);
        String coreAttestUrl = this.config.getString(Const.Config.CoreAttestUrlProp);
        DownloadCloudStorage fsStores;
        if (coreAttestUrl != null) {
            String coreApiToken = this.config.getString(Const.Config.CoreApiTokenProp);
            Duration disableWaitTime = Duration.ofHours(this.config.getInteger(Const.Config.FailureShutdownWaitHoursProp, 120));
            this.disableHandler = new OperatorDisableHandler(disableWaitTime, Clock.systemUTC());
            UidCoreClient coreClient = createUidCoreClient(coreAttestUrl, coreApiToken, this.disableHandler::handleResponseStatus);
            fsStores = coreClient;
            LOGGER.info("Salt/Key/Client stores - Using uid2-core attestation endpoint: " + coreAttestUrl);

            if (useStorageMock) {
                this.fsOptOut = configureMockOptOutStore();
            } else {
                this.fsOptOut = configureAttestedOptOutStore(coreClient, coreAttestUrl);
            }
        } else if (useStorageMock) {
            fsStores = new EmbeddedResourceStorage(Main.class);
            LOGGER.info("Salt/Key/Client stores - Using EmbeddedResourceStorage");

            this.fsOptOut = configureMockOptOutStore();
        } else {
            String coreBucket = this.config.getString(Const.Config.CoreS3BucketProp);
            fsStores = CloudUtils.createStorage(coreBucket, config);
            LOGGER.info("Salt/Key/Client stores - Using the same storage as optout: s3://" + coreBucket);

            this.fsOptOut = configureCloudOptOutStore();
        }

        String clientsMdPath = this.config.getString(Const.Config.ClientsMetadataPathProp);
        this.clientKeyProvider = new RotatingClientKeyProvider(fsStores, new GlobalScope(new CloudPath(clientsMdPath)));
        String keysMdPath = this.config.getString(Const.Config.KeysMetadataPathProp);
        this.keyStore = new RotatingKeyStore(fsStores, new GlobalScope(new CloudPath(keysMdPath)));
        String keysAclMdPath = this.config.getString(Const.Config.KeysAclMetadataPathProp);
        this.keyAclProvider = new RotatingKeyAclProvider(fsStores, new GlobalScope(new CloudPath(keysAclMdPath)));
        String saltsMdPath = this.config.getString(Const.Config.SaltsMetadataPathProp);
        this.saltProvider = new RotatingSaltProvider(fsStores, saltsMdPath);

        this.optOutStore = new CloudSyncOptOutStore(vertx, fsLocal, this.config);

        if (useStorageMock && coreAttestUrl == null) {
            this.clientKeyProvider.loadContent();
            this.keyStore.loadContent();
            this.keyAclProvider.loadContent();
            this.saltProvider.loadContent();
        }

        metrics = new OperatorMetrics(keyStore, saltProvider);
    }

    public static void main(String[] args) throws Exception {

        java.security.Security.setProperty("networkaddress.cache.ttl" , "60");

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
                LOGGER.error("Unable to read config: " + ar.cause().getMessage(), ar.cause());
                return;
            }

            try {
                Main app = new Main(vertx, ar.result());
                app.run();
            } catch (Exception e) {
                LOGGER.error("Error: " + e.getMessage(), e);
                ((LoggerContext)org.slf4j.LoggerFactory.getILoggerFactory()).stop(); // flush logs before shutdown
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
            UIDOperatorVerticle verticle = new UIDOperatorVerticle(config, clientKeyProvider, keyStore, keyAclProvider, saltProvider, optOutStore, Clock.systemUTC(), _statsCollectorQueue);
            if (this.disableHandler != null)
                verticle.setDisableHandler(this.disableHandler);
            return verticle;
        };

        DeploymentOptions options = new DeploymentOptions();
        int svcInstances = this.config.getInteger(Const.Config.ServiceInstancesProp);
        options.setInstances(svcInstances);

        Promise<Void> compositePromise = Promise.promise();
        List<Future> fs = new ArrayList<>();
        fs.add(createAndDeployStatsCollector());
        fs.add(createStoreVerticles());

        CompositeFuture.all(fs).onComplete(ar -> {
            if (ar.failed()) compositePromise.fail(new Exception(ar.cause()));
            else compositePromise.complete();
        });

        compositePromise.future()
            .compose(v -> {
                metrics.setup();
                vertx.setPeriodic(60000, id -> metrics.update());

                Promise<String> promise = Promise.promise();
                vertx.deployVerticle(operatorVerticleSupplier, options, promise);
                return promise.future();
            })
            .onFailure(t -> {
                LOGGER.error("Failed to bootstrap operator: " + t.getMessage(), new Exception(t));
                vertx.close();
                System.exit(1);
            });
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
        vertx.deployVerticle(saltStoreVerticle, promise);
        return promise.future();
    }

    private Future<String> createAndDeployCloudSyncStoreVerticle(String name, ICloudStorage fsCloud,
                                                                 ICloudSync cloudSync) {
        Promise<String> promise = Promise.promise();
        CloudSyncVerticle cloudSyncVerticle = new CloudSyncVerticle(name, fsCloud, fsLocal, cloudSync, config);
        vertx.deployVerticle(cloudSyncVerticle, promise);
        return promise.future()
            .onComplete(v -> setupTimerEvent(cloudSyncVerticle.eventRefresh()));
    }

    private Future<String> createAndDeployStatsCollector() {
        Promise<String> promise = Promise.promise();
        StatsCollectorVerticle statsCollectorVerticle = new StatsCollectorVerticle(60000);
        vertx.deployVerticle(statsCollectorVerticle, promise);
        _statsCollectorQueue = statsCollectorVerticle;
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
                .meterFilter(MeterFilter.replaceTagValues(Label.HTTP_PATH.toString(), actualPath -> {
                    try {
                        return HttpUtils.normalizePath(actualPath).split("\\?")[0];
                    } catch (IllegalArgumentException e) {
                        return actualPath;
                    }
                }))
                // Don't record metrics for 404s.
                .meterFilter(MeterFilter.deny(id ->
                    id.getName().startsWith(MetricsDomain.HTTP_SERVER.getPrefix()) &&
                    Objects.equals(id.getTag(Label.HTTP_CODE.toString()), "404")))
                .meterFilter(new MeterFilter() {
                    private final String httpServerResponseTime = MetricsDomain.HTTP_SERVER.getPrefix() + MetricsNaming.v4Names().getHttpResponseTime();

                    @Override
                    public DistributionStatisticConfig configure(Meter.Id id, DistributionStatisticConfig config) {
                        if (id.getName().equals(httpServerResponseTime)) {
                            return DistributionStatisticConfig.builder()
                                .percentiles(0.90, 0.95, 0.99)
                                .build()
                                .merge(config);
                        }
                        return config;
                    }
                })
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

    private UidCoreClient createUidCoreClient(String attestationUrl, String userToken, Handler<Integer> responseWatcher) throws Exception {
        String enclavePlatform = this.config.getString("enclave_platform", "");
        if (enclavePlatform == null) {
            enclavePlatform = "";
        }
        Boolean enforceHttps = this.config.getBoolean("enforce_https", true);
        AttestationTokenRetriever attestationTokenRetriever;

        switch (enclavePlatform) {
            case "aws-nitro":
                LOGGER.info("creating uid core client with aws attestation protocol");
                attestationTokenRetriever = new AttestationTokenRetriever(vertx, attestationUrl, userToken, this.appVersion, AttestationFactory.getNitroAttestation(), responseWatcher);
                break;
            case "gcp-vmid":
                LOGGER.info("creating uid core client with gcp vmid attestation protocol");
                attestationTokenRetriever = new AttestationTokenRetriever(vertx, attestationUrl, userToken, this.appVersion, AttestationFactory.getGcpVmidAttestation(), responseWatcher);
                break;
            case "gcp-oidc":
                LOGGER.info("creating uid core client with gcp oidc attestation protocol");
                attestationTokenRetriever = new AttestationTokenRetriever(vertx, attestationUrl, userToken, this.appVersion, AttestationFactory.getGcpOidcAttestation(), responseWatcher);
                break;
            case "azure-sgx":
                LOGGER.info("creating uid core client with azure sgx attestation protocol");
                attestationTokenRetriever = new AttestationTokenRetriever(vertx, attestationUrl, userToken, this.appVersion, AttestationFactory.getAzureAttestation(), responseWatcher);
                break;
            default:
                attestationTokenRetriever = new AttestationTokenRetriever(vertx, attestationUrl, userToken, this.appVersion, new NoAttestationProvider(), responseWatcher);
        }
        return new UidCoreClient(userToken, CloudUtils.defaultProxy, enforceHttps, attestationTokenRetriever);
    }
}
