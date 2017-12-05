package com.vigorous.fingerprintchecker.fingerprint;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import com.vigorous.fingerprintchecker.exception.FingerPrintInvalidException;
import com.vigorous.fingerprintchecker.utils.AndroidPermissionUtil;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by vigorous.liang on 2017/11/30.
 */
public class FingerprintHelper {
    private static final String TAG = FingerprintHelper.class.getName();
    private static FingerprintHelper mFingerprintHelper;
    private Context mContext;

    private FingerprintManager manager;
    private CancellationSignal mCancellationSignal;
    private FingerPrintAuthenticationCallback mCallback;
    private FingerPrintAndroidKeyStore mLocalAndroidKeyStore;

    public final static int APPLY = KeyProperties.PURPOSE_ENCRYPT;
    public final static int VERIFY = KeyProperties.PURPOSE_DECRYPT;

    public final static int FINGERPRINT_UNSUPPORT = -1;
    public final static int FINGERPRINT_UNAVAILABLE = 0;
    public final static int FINGERPRINT_AVAILABLE = 1;

    private static int mCurrentKeyProperties;
    private static String mCurrentKeyName;
    private static String mCurrentFingerToken;
    private static String mCurrentIV;
    private int mFingerPrintSupportStatus = FINGERPRINT_UNSUPPORT;

    private FingerprintHelper(Context context) {
        if (context != null) {
            mContext = context.getApplicationContext();
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    manager = context
                            .getSystemService(FingerprintManager.class);
                }
                mLocalAndroidKeyStore = new FingerPrintAndroidKeyStore();
                mFingerPrintSupportStatus = checkFingerprintAvailable();
            } catch (Throwable t) {
                Log.e(TAG, t.getMessage());
                t.printStackTrace();
            }
        }
    }

    /**
     * Get FingerprintHelper instance. Create it if is unavailable
     *
     * @param context
     * @return
     */
    public static FingerprintHelper getInstance(Context context) {
        if (null != context && null == mFingerprintHelper) {
            synchronized (FingerprintHelper.class) {
                if (null != context && null == mFingerprintHelper) {
                    mFingerprintHelper = new FingerprintHelper(context);
                }
            }
        }
        return mFingerprintHelper;
    }

    /**
     * Get FingerprintHelper instance if is available.
     *
     * @return FingerprintHelper instance can be null if is unavailable.
     */
    public static FingerprintHelper getInstance() {
        if (null != mFingerprintHelper) {
            return mFingerprintHelper;
        } else {
            return null;
        }
    }

    /**
     * Supply to set the fingerprint check before using the card
     *
     * @param keyName HCECardId
     * @param purpose FingerprintHelper.APPLY or FingerprintHelper.VERIFY
     * @param IV IV cant not be empty when purpose equals to VERIFY.
     * @return
     */
    public boolean authenticate(String keyName, int purpose, String fingerToken,
            String IV, FingerPrintAuthenticationCallback callback)
            throws FingerPrintInvalidException {
        if (mFingerPrintSupportStatus != FINGERPRINT_AVAILABLE) {
            if (callback != null) {
                callback.onAuthenticationFail("Fail");
            }
            return false;
        }
        this.mCurrentKeyProperties = purpose;
        // cardId
        this.mCurrentKeyName = keyName;
        // encrypted Data
        this.mCurrentFingerToken = fingerToken;
        // IV
        this.mCurrentIV = IV;
        this.mCallback = callback;

        try {
            FingerprintManager.CryptoObject object;
            if (purpose == KeyProperties.PURPOSE_DECRYPT) {
                object = mLocalAndroidKeyStore.getCryptoObject(keyName,
                        Cipher.DECRYPT_MODE,
                        Base64.decode(IV, Base64.URL_SAFE));
                if (object == null) {
                    return false;
                }
            } else {
                object = mLocalAndroidKeyStore.getCryptoObject(keyName,
                        Cipher.ENCRYPT_MODE, null);
            }
            mCancellationSignal = new CancellationSignal();
            if (manager != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    FingerprintManager.AuthenticationCallback authenticationCallback = new FingerprintManager.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(
                                FingerprintManager.AuthenticationResult result) {
                            Log.e(TAG, "FingerPrint Authentication Succeeded");
                            if (mCallback == null) {
                                Log.e(TAG, "mCallback is null");
                                return;
                            }
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                if (result.getCryptoObject() == null) {
                                    Log.e(TAG,
                                            "result.getCryptoObject() == null");
                                    mCallback.onAuthenticationFail(
                                            "Authentication Fail");
                                    return;
                                }
                            }
                            Cipher cipher = null;
                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                                cipher = result.getCryptoObject().getCipher();
                            }
                            if (mCurrentKeyProperties == KeyProperties.PURPOSE_DECRYPT) {
                                // 取出secret key并返回
                                if (TextUtils.isEmpty(mCurrentKeyName)) {
                                    mCallback.onAuthenticationFail(
                                            "Authentication is available");
                                    return;
                                }
                                try {
                                    if (cipher != null) {
                                        byte[] decrypted = cipher.doFinal(Base64
                                                .decode(mCurrentFingerToken,
                                                        Base64.URL_SAFE));
                                        if (mContext.getPackageName().equals(
                                                new String(decrypted))) {
                                            mCallback.onAuthenticationSucceeded(
                                                    new String(decrypted),
                                                    mCurrentKeyProperties, "");
                                        } else {
                                            mCallback.onAuthenticationFail(
                                                    "Authentication Fail");
                                        }
                                    } else {
                                        mCallback.onAuthenticationFail(
                                                "Authentication Fail");
                                    }
                                } catch (BadPaddingException
                                        | IllegalBlockSizeException e) {
                                    e.printStackTrace();
                                    mCallback.onAuthenticationFail(
                                            "Authentication exception");
                                }
                            } else if (mCurrentKeyProperties == KeyProperties.PURPOSE_ENCRYPT) {
                                // 将前面生成的data包装成secret key，存入沙盒
                                try {
                                    byte[] encrypted = cipher.doFinal(mContext
                                            .getPackageName().getBytes());
                                    byte[] IV = cipher.getIV();
                                    String se = Base64.encodeToString(encrypted,
                                            Base64.URL_SAFE);
                                    String siv = Base64.encodeToString(IV,
                                            Base64.URL_SAFE);
                                    mCallback.onAuthenticationSucceeded(se,
                                            mCurrentKeyProperties, siv);
                                } catch (BadPaddingException
                                        | IllegalBlockSizeException e) {
                                    e.printStackTrace();
                                    mCallback.onAuthenticationFail(
                                            "Authentication exception");
                                }
                            }
                        }

                        @Override
                        public void onAuthenticationError(int errorCode,
                                CharSequence errString) {
                            Log.e(TAG, "FingerPrint onAuthentication Error");
                            if (mCallback != null) {
                                mCallback.onAuthenticationOverLimit(
                                        errString.toString());
                            }
                        }

                        @Override
                        public void onAuthenticationHelp(int helpCode,
                                CharSequence helpString) {
                            Log.e(TAG, "FingerPrint Authentication help");
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            Log.e(TAG, "FingerPrint Authentication Failed");
                            if (mCallback != null) {
                                mCallback.onAuthenticationFail(
                                        "Authentication exception");
                            }
                        }
                    };
                    manager.authenticate(object, mCancellationSignal, 0,
                            authenticationCallback, null);
                }
            }
            return true;
        } catch (SecurityException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * generateKey when user apply to encrypt
     *
     * @param keyName
     * @return
     */
    public boolean generateKey(String keyName) {
        boolean result = false;
        // 在keystore中生成加密密钥
        if (null != mLocalAndroidKeyStore
                && mFingerPrintSupportStatus == FINGERPRINT_AVAILABLE) {
            result = mLocalAndroidKeyStore.generateKey(keyName);
        }
        return result;
    }

    public void stopAuthenticate() {
        if (mCancellationSignal != null) {
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
        mCallback = null;
    }

    /**
     * @return FINGERPRINT_UNAVAILABLE 支持指纹但是没有录入指纹；
     *         FINGERPRINT_AVAILABLE：有可用指纹； FINGERPRINT_UNSUPPORT，手机不支持指纹
     */
    public int checkFingerprintAvailable() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.e(TAG, "checkFingerprintAvailable:SDK_int");
            return FINGERPRINT_UNSUPPORT;
        }
        if (!isKeyProtectedEnforcedBySecureHardware()) {
            Log.e(TAG,
                    "checkFingerprintAvailable:isKeyProtectedEnforcedBySecureHardware");
            return FINGERPRINT_UNSUPPORT;
        } else {
            boolean isFingerPrintGranted = false;
            try {
                isFingerPrintGranted = AndroidPermissionUtil.checkPermission(
                        mContext, AndroidPermissionUtil.CODE_FINGERPRINT);
            } catch (RuntimeException e) {
                Log.e(TAG,
                        "checkFingerprintAvailable:checkSelfPermission exception");
                return FINGERPRINT_UNSUPPORT;
            }
            if (isFingerPrintGranted) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (!manager.isHardwareDetected()) {
                        Log.e(TAG,
                                "checkFingerprintAvailable:isHardwareDetected");
                        return FINGERPRINT_UNSUPPORT;
                    } else if (!manager.hasEnrolledFingerprints()) {
                        Log.e(TAG,
                                "checkFingerprintAvailable:hasEnrolledFingerprints");
                        return FINGERPRINT_UNAVAILABLE;
                    }
                } else {
                    return FINGERPRINT_UNSUPPORT;
                }
            }
        }
        return FINGERPRINT_AVAILABLE;
    }

    public boolean isKeyProtectedEnforcedBySecureHardware() {
        if (null != mLocalAndroidKeyStore) {
            return mLocalAndroidKeyStore
                    .isKeyProtectedEnforcedBySecureHardware();
        } else {
            Log.e(TAG,
                    "isKeyProtectedEnforcedBySecureHardware:mLocalAndroidKeyStore is null");
            return false;
        }
    }

}
