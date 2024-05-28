package com.uid2.operator.vertx;

import com.uid2.shared.Const;
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
import java.util.Map;

public class ClientVersionCapturingHandler implements Handler<RoutingContext> {
    private final Map<String, Counter> _clientVersionCounters = new HashMap<>();

    public ClientVersionCapturingHandler(String dir, String whitelistGlob) throws IOException {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(Paths.get(dir), whitelistGlob)) {
            dirStream.forEach(path -> {
                final String version = getFileNameWithoutExtension(path);
                final Counter counter = Counter
                        .builder("uid2.client_sdk_versions")
                        .description("counter for how many http requests are processed per each client sdk version")
                        .tags("client_version", version)
                        .register(Metrics.globalRegistry);
                _clientVersionCounters.put(version, counter);
            });
        }
    }
    @Override
    public void handle(RoutingContext context) {
        String clientVersion = context.request().headers().get(Const.Http.ClientVersionHeader);
        if (clientVersion == null) {
            clientVersion =  !context.queryParam("client").isEmpty() ? context.queryParam("client").get(0) : null;
        }
        if (clientVersion != null) {
            final Counter counter = _clientVersionCounters.get(clientVersion);
            if (counter != null) {
                counter.increment();
            }
        }
        context.next();
    }

    private static String getFileNameWithoutExtension(Path path) {
        final String fileName = path.getFileName().toString();
        return fileName.indexOf(".") > 0 ? fileName.substring(0, fileName.lastIndexOf(".")) : fileName;
    }
}
