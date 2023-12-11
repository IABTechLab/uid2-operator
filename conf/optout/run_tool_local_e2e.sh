#!/bin/sh

java -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=./conf/logback.xml \
    -cp uid2-optout.jar \
    com.uid2.optout.tool.OptOutLogTool \
    $*
