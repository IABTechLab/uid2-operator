package com.uid2.operator.monitoring;

public interface ILoggedStat {
    public String GetLogPrefix();
    public Object GetValueToLog();
}
