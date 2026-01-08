package com.uid2.operator.util;

import com.uid2.operator.vertx.Endpoints;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HTTPPathMetricFilterOptimizedTest {
    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "/",
            "/unknown-path",
            "../",
            "/v1/identity/map%55",
            "/list/123",
    })
    void testPathFiltering_InvalidPaths_Unknown(String actualPath) {
        String filteredPath = HTTPPathMetricFilterOptimized.filterPath(actualPath, Endpoints.pathSet());
        assertEquals("/unknown", filteredPath);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "v1/identity/map?id=bad-escape-code%2",
            "token/refresh?refresh_token=SOME_TOKEN<%=7485*4353%>",
            "list/12%4/5435"
    })
    void testPathFiltering_InvalidPaths_ParsingError(String actualPath) {
        String filteredPath = HTTPPathMetricFilterOptimized.filterPath(actualPath, Endpoints.pathSet());
        assertEquals("/parsing_error", filteredPath);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "/v2/identity/map, /v2/identity/map",
            "v2/identity/map, /v2/identity/map",
            "V3/IdenTity/mAp, /v3/identity/map",
            "v2/token/refresh?refresh_token=123%20%23, /v2/token/refresh",
            "v2/identity/map?identity/../map/, /v2/identity/map"
    })
    void testPathFiltering_ValidPaths_KnownEndpoints(String actualPath, String expectedFilteredPath) {
        String filteredPath = HTTPPathMetricFilterOptimized.filterPath(actualPath, Endpoints.pathSet());
        assertEquals(expectedFilteredPath, filteredPath);
    }
}
