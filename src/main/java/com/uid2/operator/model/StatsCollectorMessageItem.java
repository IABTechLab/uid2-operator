package com.uid2.operator.model;

public class StatsCollectorMessageItem {
    private String path;
    private String referer;
    private String apiContact;
    private Integer siteId;

    //USED by json serial
    public StatsCollectorMessageItem(){}

    public StatsCollectorMessageItem(String path, String referer, String apiContact, Integer siteId){
        this.path = path;
        this.referer = referer;
        this.apiContact = apiContact;
        this.siteId = siteId;
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
}
