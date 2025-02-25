package com.uid2.operator.vertx;

import com.uid2.operator.util.Tuple;
import com.uid2.shared.Const;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.IAuthorizableProvider;
import com.uid2.shared.middleware.AuthMiddleware;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientVersionCapturingHandler.class);
    private static final String BEARER_TOKEN_PREFIX = "bearer ";
    private final Map<Tuple.Tuple2<String, String>, Counter> _clientVersionCounters = new HashMap<>();
    private IAuthorizableProvider authKeyStore;
    private final Set<String> versions = new HashSet<>();

    public ClientVersionCapturingHandler(String dir, String whitelistGlob, IAuthorizableProvider authKeyStore) throws IOException {
        this.authKeyStore = authKeyStore;
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(Paths.get(dir), whitelistGlob)) {
            dirStream.forEach(path -> {
                final String version = getFileNameWithoutExtension(path);
                versions.add(version);
            });
        }
    }
    @Override
    public void handle(RoutingContext context) {
        String clientVersion = context.request().headers().get(Const.Http.ClientVersionHeader);
        if (clientVersion == null) {
            clientVersion =  !context.queryParam("client").isEmpty() ? context.queryParam("client").get(0) : null;
        }
        String apiContact;
        // remove in UID2-4990
        apiContact = !context.queryParam("apiContact").isEmpty() ? context.queryParam("apiContact").get(0) : null;
        if (apiContact == null) {
            try {
                final String authHeaderValue = context.request().getHeader("Authorization");
                final String authKey = extractBearerToken(authHeaderValue);
                final IAuthorizable profile = this.authKeyStore.get(authKey);
                apiContact = profile.getContact();
                apiContact = apiContact == null ? "unknown" : apiContact;
            } catch (Exception ex) {
                apiContact = "unknown";
            }
        }
        if (clientVersion != null && versions.contains(clientVersion)) {
            _clientVersionCounters.computeIfAbsent(new Tuple.Tuple2<>(apiContact, clientVersion), tuple -> Counter
                    .builder("uid2.client_sdk_versions")
                    .description("counter for how many http requests are processed per each client sdk version")
                    .tags("api_contact", tuple.getItem1(), "client_version", tuple.getItem2())
                    .register(Metrics.globalRegistry)).increment();;
        }
        context.next();
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

        if (!BEARER_TOKEN_PREFIX.equals(givenPrefix.toLowerCase())) {
            return null;
        }
        return v.substring(BEARER_TOKEN_PREFIX.length());
    }
}