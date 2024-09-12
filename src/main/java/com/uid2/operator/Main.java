package com.uid2.operator;

import ch.qos.logback.classic.LoggerContext;
import com.google.common.base.Strings;
import com.uid2.enclave.IAttestationProvider;
import com.uid2.enclave.IOperatorKeyRetriever;
import com.uid2.operator.model.KeyManager;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.OperatorMetrics;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import com.uid2.operator.service.SecureLinkValidatorService;
import com.uid2.operator.service.ShutdownService;
import com.uid2.operator.vertx.Endpoints;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.operator.store.CloudSyncOptOutStore;
import com.uid2.operator.store.OptOutCloudStorage;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.ApplicationVersion;
import com.uid2.shared.Utils;
import com.uid2.shared.attest.*;
import com.uid2.shared.cloud.*;
import com.uid2.shared.jmx.AdminApi;
import com.uid2.shared.optout.OptOutCloudSync;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.store.reader.*;
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
import io.vertx.micrometer.backends.BackendRegistries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
    private final RotatingSiteStore siteProvider;
    private final RotatingClientKeyProvider clientKeyProvider;
    private final RotatingKeysetKeyStore keysetKeyStore;
    private final RotatingKeysetProvider keysetProvider;
    private final RotatingClientSideKeypairStore clientSideKeypairProvider;
    private final RotatingSaltProvider saltProvider;
    private final CloudSyncOptOutStore optOutStore;
    private OperatorShutdownHandler shutdownHandler = null;
    private final OperatorMetrics metrics;
    private final boolean clientSideTokenGenerate;
    private final boolean validateServiceLinks;
    private IStatsCollectorQueue _statsCollectorQueue;
    private RotatingServiceStore serviceProvider;
    private RotatingServiceLinkStore serviceLinkProvider;

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
        this.clientSideTokenGenerate = config.getBoolean(Const.Config.EnableClientSideTokenGenerate, false);
        this.validateServiceLinks = config.getBoolean(Const.Config.ValidateServiceLinks, false);
        this.shutdownHandler = new OperatorShutdownHandler(Duration.ofHours(12), Duration.ofHours(config.getInteger(Const.Config.SaltsExpiredShutdownHours, 12)), Clock.systemUTC(), new ShutdownService());

        String coreAttestUrl = this.config.getString(Const.Config.CoreAttestUrlProp);

        var operatorKeyRetriever = createOperatorKeyRetriever();
        var operatorKey = operatorKeyRetriever.retrieve();

        DownloadCloudStorage fsStores;
        if (coreAttestUrl != null) {

            var clients = createUidClients(this.vertx, coreAttestUrl, operatorKey, this.shutdownHandler::handleAttestResponse);
            UidCoreClient coreClient = clients.getKey();
            UidOptOutClient optOutClient = clients.getValue();
            fsStores = coreClient;
            LOGGER.info("Salt/Key/Client stores - Using uid2-core attestation endpoint: " + coreAttestUrl);

            if (useStorageMock) {
                this.fsOptOut = configureMockOptOutStore();
            } else {
                this.fsOptOut = configureAttestedOptOutStore(optOutClient, coreAttestUrl);
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

        String sitesMdPath = this.config.getString(Const.Config.SitesMetadataPathProp);
        String keypairMdPath = this.config.getString(Const.Config.ClientSideKeypairsMetadataPathProp);
        this.clientSideKeypairProvider = new RotatingClientSideKeypairStore(fsStores, new GlobalScope(new CloudPath(keypairMdPath)));
        String clientsMdPath = this.config.getString(Const.Config.ClientsMetadataPathProp);
        this.clientKeyProvider = new RotatingClientKeyProvider(fsStores, new GlobalScope(new CloudPath(clientsMdPath)));
        String keysetKeysMdPath = this.config.getString(Const.Config.KeysetKeysMetadataPathProp);
        this.keysetKeyStore = new RotatingKeysetKeyStore(fsStores, new GlobalScope(new CloudPath(keysetKeysMdPath)));
        String keysetMdPath = this.config.getString(Const.Config.KeysetsMetadataPathProp);
        this.keysetProvider = new RotatingKeysetProvider(fsStores, new GlobalScope(new CloudPath(keysetMdPath)));
        String saltsMdPath = this.config.getString(Const.Config.SaltsMetadataPathProp);
        this.saltProvider = new RotatingSaltProvider(fsStores, saltsMdPath);
        this.optOutStore = new CloudSyncOptOutStore(vertx, fsLocal, this.config, operatorKey, Clock.systemUTC());

        if (this.validateServiceLinks) {
            String serviceMdPath = this.config.getString(Const.Config.ServiceMetadataPathProp);
            this.serviceProvider = new RotatingServiceStore(fsStores, new GlobalScope(new CloudPath(serviceMdPath)));
            String serviceLinkMdPath = this.config.getString(Const.Config.ServiceLinkMetadataPathProp);
            this.serviceLinkProvider = new RotatingServiceLinkStore(fsStores, new GlobalScope(new CloudPath(serviceLinkMdPath)));
        }

        this.siteProvider = clientSideTokenGenerate ? new RotatingSiteStore(fsStores, new GlobalScope(new CloudPath(sitesMdPath))) : null;

        if (useStorageMock && coreAttestUrl == null) {
            if (clientSideTokenGenerate) {
                this.siteProvider.loadContent();
                this.clientSideKeypairProvider.loadContent();
            }
            this.clientKeyProvider.loadContent();
            this.saltProvider.loadContent();
            this.keysetProvider.loadContent();
            this.keysetKeyStore.loadContent();

            if (this.validateServiceLinks) {
                this.serviceProvider.loadContent();
                this.serviceLinkProvider.loadContent();
            }

            try {
                getKeyManager().getMasterKey();
            } catch (KeyManager.NoActiveKeyException e) {
                LOGGER.error("No active master key found", e);
                System.exit(1);
            }
            if (saltProvider.getSnapshot(Instant.now()).getExpires().isBefore(Instant.now())) {
                LOGGER.error("all salts are expired");
                System.exit(1);
            }
        }
        metrics = new OperatorMetrics(getKeyManager(), saltProvider);
    }

    private KeyManager getKeyManager() {
        return new KeyManager(this.keysetKeyStore, this.keysetProvider);
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

    private ICloudStorage configureAttestedOptOutStore(UidOptOutClient optOutClient, String coreAttestUrl) {
        String optOutMdPath = this.config.getString(Const.Config.OptOutMetadataPathProp);
        LOGGER.info("OptOut stores- Using uid2-core attestation endpoint: " + coreAttestUrl);
        return this.wrapCloudStorageForOptOut(new OptOutCloudStorage(optOutClient, optOutMdPath, CloudUtils.defaultProxy));
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
            UIDOperatorVerticle verticle = new UIDOperatorVerticle(config, this.clientSideTokenGenerate, siteProvider, clientKeyProvider, clientSideKeypairProvider, getKeyManager(), saltProvider, optOutStore, Clock.systemUTC(), _statsCollectorQueue, new SecureLinkValidatorService(this.serviceLinkProvider, this.serviceProvider), this.shutdownHandler::handleSaltRetrievalResponse);
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
        if (clientSideTokenGenerate) {
            siteProvider.getMetadata();
            clientSideKeypairProvider.getMetadata();
        }
        clientKeyProvider.getMetadata();
        keysetKeyStore.getMetadata();
        keysetProvider.getMetadata();
        saltProvider.getMetadata();

        if (validateServiceLinks) {
            serviceProvider.getMetadata();
            serviceLinkProvider.getMetadata();
        }

        // create cloud sync for optout store
        OptOutCloudSync optOutCloudSync = new OptOutCloudSync(config, false);
        this.optOutStore.registerCloudSync(optOutCloudSync);

        // create rotating store verticles to poll for updates
        Promise<Void> promise = Promise.promise();
        List<Future> fs = new ArrayList<>();
        if (clientSideTokenGenerate) {
            fs.add(createAndDeployRotatingStoreVerticle("site", siteProvider, "site_refresh_ms"));
            fs.add(createAndDeployRotatingStoreVerticle("client_side_keypairs", clientSideKeypairProvider, "client_side_keypairs_refresh_ms"));
        }
        fs.add(createAndDeployRotatingStoreVerticle("auth", clientKeyProvider, "auth_refresh_ms"));
        fs.add(createAndDeployRotatingStoreVerticle("keyset", keysetProvider, "keyset_refresh_ms"));
        fs.add(createAndDeployRotatingStoreVerticle("keysetkey", keysetKeyStore, "keysetkey_refresh_ms"));
        fs.add(createAndDeployRotatingStoreVerticle("salt", saltProvider, "salt_refresh_ms"));
        fs.add(createAndDeployCloudSyncStoreVerticle("optout", fsOptOut, optOutCloudSync));
        CompositeFuture.all(fs).onComplete(ar -> {
            if (ar.failed()) promise.fail(new Exception(ar.cause()));
            else promise.complete();
        });

        if (validateServiceLinks) {
            fs.add(createAndDeployRotatingStoreVerticle("service", serviceProvider, "service_refresh_ms"));
            fs.add(createAndDeployRotatingStoreVerticle("service_link", serviceLinkProvider, "service_link_refresh_ms"));
        }

        return promise.future();
    }

    private Future<String> createAndDeployRotatingStoreVerticle(String name, IMetadataVersionedStore store, String storeRefreshConfigMs) {
        final int intervalMs = config.getInteger(storeRefreshConfigMs, 10000);

        RotatingStoreVerticle rotatingStoreVerticle = new RotatingStoreVerticle(name, intervalMs, store);
        Promise<String> promise = Promise.promise();
        vertx.deployVerticle(rotatingStoreVerticle, promise);
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
        StatsCollectorVerticle statsCollectorVerticle = new StatsCollectorVerticle(60000, config.getInteger(Const.Config.MaxInvalidPaths, 50));
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
                        String normalized = HttpUtils.normalizePath(actualPath).split("\\?")[0];
                        return Endpoints.pathSet().contains(normalized) ? normalized : "/unknown";
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

    private Map.Entry<UidCoreClient, UidOptOutClient> createUidClients(Vertx vertx, String attestationUrl, String clientApiToken, Handler<Pair<Integer, String>> responseWatcher) throws Exception {
        AttestationResponseHandler attestationResponseHandler = getAttestationTokenRetriever(vertx, attestationUrl, clientApiToken, responseWatcher);
        UidCoreClient coreClient = new UidCoreClient(clientApiToken, CloudUtils.defaultProxy, attestationResponseHandler);
        UidOptOutClient optOutClient = new UidOptOutClient(clientApiToken, CloudUtils.defaultProxy, attestationResponseHandler);
        return new AbstractMap.SimpleEntry<>(coreClient, optOutClient);
    }

    private AttestationResponseHandler getAttestationTokenRetriever(Vertx vertx, String attestationUrl, String clientApiToken, Handler<Pair<Integer, String>> responseWatcher) throws Exception {
        String enclavePlatform = this.config.getString(Const.Config.EnclavePlatformProp);
        String operatorType = this.config.getString(Const.Config.OperatorTypeProp, "");

        IAttestationProvider attestationProvider;
        switch (enclavePlatform) {
            case null:
            case "":
                LOGGER.info("creating uid core client with trusted attestation protocol");
                attestationProvider = new NoAttestationProvider();
                break;
            case "aws-nitro":
                LOGGER.info("creating uid core client with aws attestation protocol");
                attestationProvider = AttestationFactory.getNitroAttestation();
                break;
            case "gcp-vmid":
                LOGGER.info("creating uid core client with gcp vmid attestation protocol");
                attestationProvider = AttestationFactory.getGcpVmidAttestation();
                break;
            case "gcp-oidc":
                LOGGER.info("creating uid core client with gcp oidc attestation protocol");
                attestationProvider = AttestationFactory.getGcpOidcAttestation();
                break;
            case "azure-cc":
                LOGGER.info("creating uid core client with azure cc attestation protocol");
                String maaServerBaseUrl = this.config.getString(Const.Config.MaaServerBaseUrlProp, "https://sharedeus.eus.attest.azure.net");
                attestationProvider = AttestationFactory.getAzureCCAttestation(maaServerBaseUrl);
                break;
            default:
                throw new IllegalArgumentException(String.format("enclave_platform is providing the wrong value: %s", enclavePlatform));
        }

        return new AttestationResponseHandler(vertx, attestationUrl, clientApiToken, operatorType, this.appVersion, attestationProvider, responseWatcher, CloudUtils.defaultProxy);
    }

    private IOperatorKeyRetriever createOperatorKeyRetriever() throws Exception {
        var enclavePlatform = this.config.getString("enclave_platform");
        if (Strings.isNullOrEmpty(enclavePlatform)) {
            // default to load from config
            return () -> this.config.getString(Const.Config.CoreApiTokenProp);
        }
        switch (enclavePlatform) {
            case "aws-nitro": {
                return () -> this.config.getString(Const.Config.CoreApiTokenProp);
            }
            case "azure-cc": {
                var vaultName = this.config.getString(Const.Config.AzureVaultNameProp);
                var secretName = this.config.getString(Const.Config.AzureSecretNameProp);
                return OperatorKeyRetrieverFactory.getAzureOperatorKeyRetriever(vaultName, secretName);
            }
            case "gcp-oidc": {
                var secretVersionName = this.config.getString(Const.Config.GcpSecretVersionNameProp);
                return OperatorKeyRetrieverFactory.getGcpOperatorKeyRetriever(secretVersionName);
            }
            default: {
                throw new IllegalArgumentException(String.format("enclave_platform is providing the wrong value: %s", enclavePlatform));
            }
        }
    }
}
