package com.vulnuris.correlation.utils;

public final class Constants {

    private Constants() {} 

    public static final double EDGE_THRESHOLD = 0.40;


    public static final long TIME_WINDOW_LOW_MINUTES = 10;
    public static final long TIME_WINDOW_CRITICAL_MINUTES = 120;
    public static final double SEVERITY_CRITICAL_THRESHOLD = 7.0;


    public static final double RISK_DAMPING_FACTOR = 0.3;
    public static final int RISK_PROPAGATION_ROUNDS = 3;
    public static final double MAX_RISK = 1.0;


    public static final int CREDENTIAL_STUFFING_USER_THRESHOLD = 3;


    public static final int GEOIP_TIMEOUT_SECONDS = 5;
    public static final int CISA_KEV_TIMEOUT_SECONDS = 15;
    public static final int REDIS_CACHE_HOURS = 24;
}