package com.uid2.operator.model;

public class StatsCollectorMessageItem {
    private String path;
    private String referer;
    private String apiContact;
    private Integer siteId;
    private String clientVersion;
    private String remoteAddress;

    //USED by json serial
    public StatsCollectorMessageItem() {
    }

    public StatsCollectorMessageItem(String path, String referer, String apiContact, Integer siteId, String clientVersion) {
        this(path, referer, apiContact, siteId, clientVersion, "");
    }

    public StatsCollectorMessageItem(String path, String referer, String apiContact, Integer siteId, String clientVersion, String remoteAddress) {
        this.path = path;
        this.referer = referer;
        this.apiContact = apiContact;
        this.siteId = siteId;
        this.clientVersion = clientVersion;
        this.remoteAddress = remoteAddress;
    }


    public void setReferer(String referer) {
        this.referer = referer;
    }

    public String getReferer() {
        return referer;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public String getApiContact() {
        return apiContact;
    }

    public void setApiContact(String apiContact) {
        this.apiContact = apiContact;
    }

    public Integer getSiteId() {
        return siteId;
    }

    public void setSiteId(Integer siteId) {
        this.siteId = siteId;
    }

    public String getClientVersion() {
        return clientVersion;
    }

    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }
}
