package com.uid2.operator.store;

public interface IConfigStore {
    RuntimeConfig getConfig();
    void loadContent() throws Exception;
}
