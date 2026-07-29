package com.uid2.operator.vertx;

import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.junit5.VertxExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(VertxExtension.class)
class StaticHandlerCacheTest {
    private static final String SDK_PATH = "/static/js/uid2-sdk-2.0.0.js";
    private static final String POISON_PATH = "/static/bar%2F..%2Fjs/uid2-sdk-2.0.0.js";

    private HttpServer server;

    @BeforeEach
    void startServer(io.vertx.core.Vertx vertx) {
        Router router = Router.router(vertx);
        router.route("/static/*").handler(StaticHandler.create("static"));

        server = vertx.createHttpServer()
                .requestHandler(router)
                .listen(0, "127.0.0.1")
                .toCompletionStage()
                .toCompletableFuture()
                .join();
    }

    @AfterEach
    void stopServer() {
        server.close()
                .toCompletionStage()
                .toCompletableFuture()
                .join();
    }

    @Test
    void encodedDotSegmentRequestDoesNotPoisonSdkCache() throws Exception {
        // A malformed path must not cache a missing lookup under the canonical SDK path.
        assertThat(get(SDK_PATH)).isEqualTo(200);
        get(POISON_PATH);
        assertThat(get(SDK_PATH)).isEqualTo(200);
    }

    private int get(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + server.actualPort() + path))
                .GET()
                .build();

        return HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.discarding())
                .statusCode();
    }
}
