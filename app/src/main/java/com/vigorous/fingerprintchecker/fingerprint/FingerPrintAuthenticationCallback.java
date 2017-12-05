package com.vigorous.fingerprintchecker.fingerprint;
/**
 * Created by vigorous.liang on 2017/11/30.
 */
public interface FingerPrintAuthenticationCallback {
    /**
     *
     * @param result
     * @param properties
     * @param IV Store the IV when properties equals to APPLY
     */
    void onAuthenticationSucceeded(String result, int properties, String IV);

    void onAuthenticationFail(String errorMsg);

    void onAuthenticationOverLimit(String errorMsg);
}
