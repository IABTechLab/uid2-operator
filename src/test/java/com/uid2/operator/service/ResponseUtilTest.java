package com.uid2.operator.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.shared.Const;
import com.uid2.shared.auth.IAuthorizable;
import io.vertx.core.http.HttpServerRequest;
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
    private RoutingContext rc;
    private HttpServerRequest request;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(ResponseUtil.class);
        testAppender = new ListAppender<>();
        testAppender.start();
        logger.addAppender(testAppender);
        rc = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        request = mock(HttpServerRequest.class, RETURNS_DEEP_STUBS);
        when(rc.get(SecureLinkValidatorService.SERVICE_LINK_NAME, "")).thenReturn("");
        when(rc.get(SecureLinkValidatorService.SERVICE_NAME, "")).thenReturn("");
    }

    @AfterEach
    void tearDown() {
        testAppender.stop();
        logger.detachAppender(testAppender);
    }

    @Test
    void logsErrorWithNoExtraDetails() {
        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
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
        IAuthorizable mockAuthorizable = mock(IAuthorizable.class);
        when(mockAuthorizable.getContact()).thenReturn("Test Contract");
        when(mockAuthorizable.getSiteId()).thenReturn(10);
        when(rc.data().get("api-client")).thenReturn(mockAuthorizable);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":\"Test Contract\"," +
                "\"siteId\":10," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsErrorWithSiteIdFromContext() {
        when(rc.get(Const.RoutingContextData.SiteId)).thenReturn(20);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":20," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsErrorWithClientAddress() {
        io.vertx.core.net.SocketAddress socket = mock(io.vertx.core.net.SocketAddress.class);
        when(socket.hostAddress()).thenReturn("192.168.10.10");

        when(rc.request().remoteAddress()).thenReturn(socket);

        ResponseUtil.Error("Some error status", 500, rc, "Some error message");

        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":\"192.168.10.10\"," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsErrorWithServiceAndServiceLinkNames() {
        RoutingContext rc1 = mock(RoutingContext.class, RETURNS_DEEP_STUBS);
        when(rc1.get(SecureLinkValidatorService.SERVICE_LINK_NAME, "")).thenReturn("TestLink1");
        when(rc1.get(SecureLinkValidatorService.SERVICE_NAME, "")).thenReturn("TestService1");

        ResponseUtil.Error("Some error status", 500, rc1, "Some error message");
        String expected = "Error response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"statusCode\":500," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"," +
                "\"service_link_name\":\"TestLink1\"," +
                "\"service_name\":\"TestService1\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsWarningWithOrigin() {
        when(request.getHeader("origin")).thenReturn("testOriginHeader");
        when(rc.request()).thenReturn(request);

        ResponseUtil.Warning("Some error status", 400, rc, "Some error message");

        String expected = "Warning response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":400," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"," +
                "\"origin\":\"testOriginHeader\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsWarningWithOriginNull() {
        when(request.getHeader("origin")).thenReturn(null);
        when(rc.request()).thenReturn(request);

        ResponseUtil.Warning("Some error status", 400, rc, "Some error message");

        String expected = "Warning response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":400," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsWarningWithReferer() {
        when(request.getHeader("referer")).thenReturn("testRefererHeader");
        when(rc.request()).thenReturn(request);

        ResponseUtil.Warning("Some error status", 400, rc, "Some error message");

        String expected = "Warning response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":400," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"," +
                "\"referer\":\"testRefererHeader\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }

    @Test
    void logsWarningWithRefererNull() {
        when(request.getHeader("referer")).thenReturn(null);
        when(rc.request()).thenReturn(request);

        ResponseUtil.Warning("Some error status", 400, rc, "Some error message");

        String expected = "Warning response to http request. {" +
                "\"errorStatus\":\"Some error status\"," +
                "\"contact\":null," +
                "\"siteId\":null," +
                "\"path\":null," +
                "\"statusCode\":400," +
                "\"clientAddress\":null," +
                "\"message\":\"Some error message\"" +
                "}";
        ILoggingEvent loggingEvent = testAppender.list.get(0);
        assertThat(loggingEvent.getMessage()).isEqualTo(expected);
    }
}
