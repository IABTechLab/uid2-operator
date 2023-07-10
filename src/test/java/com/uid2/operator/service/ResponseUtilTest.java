package com.uid2.operator.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.shared.Const;
import com.uid2.shared.auth.IAuthorizable;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ResponseUtilTest {
    private Logger logger;
    private ListAppender<ILoggingEvent> testAppender;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(ResponseUtil.class);
        testAppender = new ListAppender<>();
        testAppender.start();
        logger.addAppender(testAppender);
    }

    @AfterEach
    void tearDown() {
        testAppender.stop();
        logger.detachAppender(testAppender);
    }

    @Test
    void logsErrorWithNoExtraDetails() {
        RoutingContext rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        assertThat(testAppender.list).hasSize(1);
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
        assertThat(loggingEvent.getLevel()).isEqualTo(Level.ERROR);
    }

    @Test
    void logsErrorWithExtraDetailsFromAuthorizable() {
        RoutingContext rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        IAuthorizable mockAuthorizable = mock(IAuthorizable.class);
        when(mockAuthorizable.getContact()).thenReturn("Test Contract");
        when(mockAuthorizable.getSiteId()).thenReturn(10);
        when(rc.data().get("api-client")).thenReturn(mockAuthorizable);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":\"Test Contract\"," +
                "\"siteId\":10," +
                "\"path\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsErrorWithSiteIdFromContext() {
        RoutingContext rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        when(rc.get(Const.RoutingContextData.SiteId)).thenReturn(20);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":20," +
                "\"path\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsErrorWithPath() {
        RoutingContext rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        when(rc.request().path()).thenReturn("some/path");

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":\"some/path\"," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }
    @Test
    void logsErrorWithClientAddress() {
        RoutingContext rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        io.vertx.core.net.SocketAddress socket = mock(io.vertx.core.net.SocketAddress.class);
        when(socket.hostAddress()).thenReturn("192.168.10.10");

        when(rc.request().remoteAddress()).thenReturn(socket);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":\"192.168.10.10\"," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }
}