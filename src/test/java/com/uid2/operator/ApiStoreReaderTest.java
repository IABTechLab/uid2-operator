package com.uid2.operator;

import com.uid2.operator.reader.ApiStoreReader;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.parser.Parser;
import com.uid2.shared.store.parser.ParsingResult;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

    class ApiStoreReaderTest {

        @Mock
        private DownloadCloudStorage mockStorage;

        @Mock
        private Parser<Collection<TestData>> mockParser;

        private final CloudPath metadataPath = new CloudPath("test/test-metadata.json");
        private final String dataType = "test-data-type";
        private final GlobalScope scope = new GlobalScope(metadataPath);

        private ApiStoreReader<Collection<TestData>> reader;

        @BeforeEach
        void setUp() {
            MockitoAnnotations.openMocks(this);
            reader = new ApiStoreReader<>(mockStorage, scope, mockParser, dataType);
        }

        @Test
        void getMetadataPathReturnsPathFromScope() {
            CloudPath actual = reader.getMetadataPath();
            assertThat(actual).isEqualTo(metadataPath);
        }

        @Test
        void loadContentThrowsExceptionWhenContentsAreNull() {
            assertThatThrownBy(() -> reader.loadContent(null, dataType))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("No contents provided for loading data type");
        }

        @Test
        void loadContentThrowsExceptionWhenArrayNotFound() {
            JsonObject contents = new JsonObject();
            assertThatThrownBy(() -> reader.loadContent(contents, dataType))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("No array found in the contents");
        }

        @Test
        void loadContentSuccessfullyLoadsData() throws Exception {
            JsonObject contents = new JsonObject()
                    .put(dataType, new JsonArray().add("value1").add("value2"));

            List<TestData> expectedData = Arrays.asList(new TestData("value1"), new TestData("value2"));
            when(mockParser.deserialize(any(InputStream.class)))
                    .thenReturn(new ParsingResult<>(expectedData, expectedData.size()));

            long count = reader.loadContent(contents, dataType);

            assertThat(count).isEqualTo(2);
            assertThat(reader.getSnapshot()).isEqualTo(expectedData);
        }

        private static class TestData {
            private final String value;

            TestData(String value) {
                this.value = value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                TestData testData = (TestData) o;
                return value.equals(testData.value);
            }

            @Override
            public int hashCode() {
                return value.hashCode();
            }
        }
    }

