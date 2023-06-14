package com.uid2.operator.model;

public enum TokenVersion {
    V2(2),
    V3(112), //prefix A3/B3 (UID2 email/phone) and E3/F3 (EUID email/phone). See UID2-79+Token+and+ID+format+v3
    V4(128); //prefix A4/B4 (UID2 email/phone) and E4/F4 (EUID email/phone)

    public final int rawVersion;

    TokenVersion(int rawVersion) { this.rawVersion = rawVersion; }
}
