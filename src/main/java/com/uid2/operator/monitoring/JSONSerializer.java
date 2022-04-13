package com.uid2.operator.monitoring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

public class JSONSerializer implements Runnable {
    private Object[] endpointStats;
    private static final Logger LOGGER = LoggerFactory.getLogger(JSONSerializer.class);

    public void setArray(Object[] stats){
        endpointStats = stats;
    }

    public void run() {
        LOGGER.debug("Starting JSON Serialize");
        ObjectMapper mapper = new ObjectMapper();
        String jsonString = null;
        for (int i = 0; i < endpointStats.length; i++) {
            try {
                jsonString = mapper.writeValueAsString(endpointStats[i]);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            LOGGER.info(jsonString);
        }
    }
}
