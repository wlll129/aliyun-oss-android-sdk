package com.alibaba.sdk.android.oss.crypto;

public enum SdkRuntime {
    ;
    /**
     * Returns true if the current operation should abort; false otherwise. Note the
     * interrupted status of the thread is cleared by this method.
     */
    public static boolean shouldAbort() {
        return Thread.interrupted();
    }
}
