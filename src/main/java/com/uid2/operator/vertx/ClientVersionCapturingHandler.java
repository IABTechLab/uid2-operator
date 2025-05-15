package com.uid2.operator.vertx;

import com.uid2.operator.util.RoutingContextUtil;
import com.uid2.operator.util.Tuple;
import com.uid2.shared.Const;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.IAuthorizableProvider;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ClientVersionCapturingHandler implements Handler<RoutingContext> {
    private static final String BEARER_TOKEN_PREFIX = "bearer ";
    private static final Map<Tuple.Tuple2<String, String>, Counter> CLIENT_VERSION_COUNTERS = new HashMap<>();
    private static final Set<String> VERSIONS = new HashSet<>();

    private final IAuthorizableProvider authKeyStore;

    public ClientVersionCapturingHandler(String dir, String whitelistGlob, IAuthorizableProvider authKeyStore) throws IOException {
        this.authKeyStore = authKeyStore;

        try (final DirectoryStream<Path> dirStream = Files.newDirectoryStream(Paths.get(dir), whitelistGlob)) {
            dirStream.forEach(path -> {
                final String version = getFileNameWithoutExtension(path);
                VERSIONS.add(version);
            });
        }
    }

    @Override
    public void handle(RoutingContext rc) {
        String clientVersion = rc.request().headers().get(Const.Http.ClientVersionHeader);
        if (clientVersion == null) {
            clientVersion = !rc.queryParam("client").isEmpty() ? rc.queryParam("client").getFirst() : null;
        }

        String apiContact;
        try {
            final String authHeaderValue = rc.request().getHeader("Authorization");
            final String authKey = extractBearerToken(authHeaderValue);
            final IAuthorizable profile = this.authKeyStore.get(authKey);
            apiContact = profile.getContact();
            apiContact = apiContact == null ? "unknown" : apiContact;
        } catch (Exception ex) {
            apiContact = "unknown";
        }

        String path = RoutingContextUtil.getPath(rc);

        if (clientVersion != null && VERSIONS.contains(clientVersion)) {
            CLIENT_VERSION_COUNTERS.computeIfAbsent(
                    new Tuple.Tuple2<>(apiContact, clientVersion),
                    tuple -> Counter
                            .builder("uid2.client_sdk_versions")
                            .description("counter for how many http requests are processed per each client sdk version")
                            .tags("api_contact", tuple.getItem1(), "client_version", tuple.getItem2(), "path", path)
                            .register(Metrics.globalRegistry)
            ).increment();
        }
        rc.next();
    }

    private static String getFileNameWithoutExtension(Path path) {
        final String fileName = path.getFileName().toString();
        return fileName.indexOf(".") > 0 ? fileName.substring(0, fileName.lastIndexOf(".")) : fileName;
    }

    private static String extractBearerToken(final String headerValue) {
        if (headerValue == null) {
            return null;
        }

        final String v = headerValue.trim();
        if (v.length() < BEARER_TOKEN_PREFIX.length()) {
            return null;
        }

        final String givenPrefix = v.substring(0, BEARER_TOKEN_PREFIX.length());

        if (!BEARER_TOKEN_PREFIX.equalsIgnoreCase(givenPrefix)) {
            return null;
        }
        return v.substring(BEARER_TOKEN_PREFIX.length());
    }
}
