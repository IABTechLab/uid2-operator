package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.service.ConfigValidatorUtil.*;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigService implements IConfigService {

    private final ConfigRetriever configRetriever;
    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);

    private ConfigService(ConfigRetriever configRetriever) {
        this.configRetriever = configRetriever;
        this.configRetriever.setConfigurationProcessor(this::configValidationHandler);
    }

    public static Future<ConfigService> create(ConfigRetriever configRetriever) {
        Promise<ConfigService> promise = Promise.promise();

        ConfigService instance = new ConfigService(configRetriever);

        // Prevent dependent classes from attempting to access configuration before it has been retrieved.
        configRetriever.getConfig(ar -> {
            if (ar.succeeded()) {
                logger.info("Successfully loaded config");
                promise.complete(instance);
            } else {
                logger.error("Failed to load config: {}", ar.cause().getMessage());
                promise.fail(ar.cause());
            }
        });

        return promise.future();
    }

    @Override
    public JsonObject getConfig() {
        return configRetriever.getCachedConfig();
    }

    private JsonObject configValidationHandler(JsonObject config) {
        boolean isValid = true;
        Integer identityExpiresAfter = config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshExpiresAfter = config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshIdentityAfter = config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        Integer maxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp, identityExpiresAfter);
        Integer sharingTokenExpiry = config.getInteger(Const.Config.SharingTokenExpiryProp);

        isValid &= validateIdentityRefreshTokens(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter);

        isValid &= validateBidstreamLifetime(maxBidstreamLifetimeSeconds, identityExpiresAfter);

        isValid &= validateSharingTokenExpiry(sharingTokenExpiry);

        if (!isValid) {
            logger.error("Failed to update config");
            JsonObject lastConfig = this.getConfig();
            if (lastConfig == null || lastConfig.isEmpty()) {
                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
            }
            return lastConfig;
        }

        logger.info("Successfully updated config");
        return config;
    }
}
"core_api_token\":\"UID2-O-I-18-Fk6QJg.ochtgQKdO6Z0N3AkuBftWLiItOKP5CNRk9QsY=\",\"storage_mock\":false,\"optout_s3_bucket\":null,\"optout_s3_folder\":\"uid-optout-integ/\",\"optout_s3_path_compat\":false,\"optout_data_dir\":\"/opt/uid2/operator-optout/\",\"optout_api_token\":\"UID2-O-I-18-Fk6QJg.ochtgQKdO6Z0N3AkuBftWLiItOKP5CNRk9QsY=\",\"optout_api_uri\":\"https://optout-integ.uidapi.com/optout/replicate\",\"optout_bloom_filter_size\":8192,\"optout_delta_rotate_interval\":300,\"optout_delta_backtrack_in_days\":1,\"optout_partition_interval\":86400,\"optout_max_partitions\":30,\"optout_heap_default_capacity\":8192,\"cloud_download_threads\":8,\"cloud_upload_threads\":2,\"cloud_refresh_interval\":60,\"sites_metadata_path\":\"https://core-integ.uidapi.com/sites/refresh\",\"clients_metadata_path\":\"https://core-integ.uidapi.com/clients/refresh\",\"client_side_keypairs_metadata_path\":\"https://core-integ.uidapi.com/client_side_keypairs/refresh\",\"keysets_metadata_path\":\"https://core-integ.uidapi.com/key/keyset/refresh\",\"keyset_keys_metadata_path\":\"https://core-integ.uidapi.com/key/keyset-keys/refresh\",\"salts_metadata_path\":\"https://core-integ.uidapi.com/salt/refresh\",\"services_metadata_path\":\"https://core-integ.uidapi.com/services/refresh\",\"service_links_metadata_path\":\"https://core-integ.uidapi.com/service_links/refresh\",\"optout_metadata_path\":\"https://optout-integ.uidapi.com/optout/refresh\",\"optout_inmem_cache\":false,\"enclave_platform\":null,\"failure_shutdown_wait_hours\":120,\"sharing_token_expiry_seconds\":2592000,\"validate_service_links\":false,\"operator_type\":\"private\",\"java.specification.version\":21,\"sun.jnu.encoding\":\"UTF-8\",\"java.class.path\":\"/app/uid2-operator-5.47.61-alpha-171-SNAPSHOT.jar\",\"java.vm.vendor\":\"Eclipse Adoptium\",\"sun.arch.data.model\":64,\"vertx-config-path\":\"/tmp/final-config.json\",\"java.vendor.url\":\"https://adoptium.net/\",\"user.timezone\":\"Etc/UTC\",\"java.vm.specification.version\":21,\"os.name\":\"Linux\",\"sun.java.launcher\":\"SUN_STANDARD\",\"user.country\":\"US\",\"sun.boot.library.path\":\"/opt/java/openjdk/lib\",\"sun.java.command\":\"/app/uid2-operator-5.47.61-alpha-171-SNAPSHOT.jar\",\"jdk.debug\":\"release\",\"sun.cpu.endian\":\"little\",\"user.home\":\"/root\",\"user.language\":\"en\",\"java.specification.vendor\":\"Oracle Corporation\",\"java.version.date\":\"2025-01-21\",\"java.home\":\"/opt/java/openjdk\",\"file.separator\":\"/\",\"line.separator\":\"\\n\",\"java.vm.specification.vendor\":\"Oracle Corporation\",\"java.specification.name\":\"Java Platform API Specification\",\"logback.configurationFile\":\"./conf/logback-debug.xml\",\"sun.management.compiler\":\"HotSpot 64-Bit Tiered Compilers\",\"java.runtime.version\":\"21.0.6+7-LTS\",\"user.name\":\"root\",\"stdout.encoding\":\"UTF-8\",\"path.separator\":\":\",\"java.security.egd\":\"file:/dev/./urandom\",\"os.version\":\"4.14.256-209.484.amzn2.x86_64\",\"java.runtime.name\":\"OpenJDK Runtime Environment\",\"file.encoding\":\"UTF-8\",\"java.vm.name\":\"OpenJDK 64-Bit Server VM\",\"java.vendor.version\":\"Temurin-21.0.6+7\",\"http_proxy\":\"socks5://127.0.0.1:3305\",\"java.vendor.url.bug\":\"https://github.com/adoptium/adoptium-support/issues\",\"java.io.tmpdir\":\"/tmp\",\"java.version\":\"21.0.6\",\"user.dir\":\"/app\",\"os.arch\":\"amd64\",\"java.vm.specification.name\":\"Java Virtual Machine Specification\",\"native.encoding\":\"UTF-8\",\"java.library.path\":\"/app/lib\",\"java.vm.info\":\"mixed mode, sharing\",\"stderr.encoding\":\"UTF-8\",\"java.vendor\":\"Eclipse Adoptium\",\"java.vm.version\":\"21.0.6+7-LTS\",\"vertx.logger-delegate-factory-class-name\":\"io.vertx.core.logging.SLF4JLogDelegateFactory\",\"sun.io.unicode.encoding\":\"UnicodeLittle\",\"java.class.version\":65.0,\"SHLVL\":1,\"LANGUAGE\":\"en_US:en\",\"JAVA_HOME\":\"/opt/java/openjdk\",\"IMAGE_VERSION\":\"5.47.61-alpha-171-SNAPSHOT-722bdd17\",\"LC_ALL\":\"en_US.UTF-8\",\"JAR_NAME\":\"uid2-operator\",\"OLDPWD\":\"/\",\"PATH\":\"/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"JAVA_VERSION\":\"jdk-21.0.6+7\",\"IDENTITY_SCOPE\":\"UID2\",\"ENCLAVE_ENVIRONMENT\":\"aws-nitro\",\"JAR_VERSION\":\"5.47.61-alpha-171-SNAPSHOT\",\"PWD\":\"/app\",\"_\":\"/opt/java/openjdk/bin/java\",\"UID2_CONFIG_SECRET_KEY\":\"uid2-operator-config-key\",\"LANG\":\"en_US.UTF-8\",\"allow_legacy_api\":false,\"runtime_config_store\":{\"type\":\"http\",\"config\":{\"url\":\"https://core-integ.uidapi.com/operator/config\"},\"config_scan_period_ms\":300000},\"identity_token_expires_after_seconds\":86400,\"refresh_token_expires_after_seconds\":2592000,\"refresh_identity_token_after_seconds\":3600,\"optout_base_url\":\"https://optout-integ.uidapi.com\",\"core_base_url\":\"https://core-integ.uidapi.com\",\"environment\":\"integ\",\"debug_mode\":true}","logger_name":"com.uid2.operator.service.ConfigService","thread_name":"vert.x-eventloop-thread-0","level":"ERROR","level_value":40000}