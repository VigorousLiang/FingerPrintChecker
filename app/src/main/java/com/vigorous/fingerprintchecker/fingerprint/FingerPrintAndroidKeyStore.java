package com.vigorous.fingerprintchecker.fingerprint;

import android.annotation.SuppressLint;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.vigorous.fingerprintchecker.exception.FingerPrintInvalidException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by vigorous.liang on 2017/11/30.
 */
@SuppressLint("NewApi")
public class FingerPrintAndroidKeyStore {
    private static final String TAG = FingerPrintAndroidKeyStore.class.getName();
    private KeyStore mStore;
    private final static String KEY_STORE_TYPE = "AndroidKeyStore";

    public FingerPrintAndroidKeyStore() {
        try {
            mStore = KeyStore.getInstance(KEY_STORE_TYPE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * generateKey
     * 
     * @param keyName
     */
    public boolean generateKey(String keyName) {
        boolean result = false;
        try {
            // 这里使用AES + CBC + PADDING_PKCS7
            final KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, KEY_STORE_TYPE);
            mStore.load(null);
            final int purpose = KeyProperties.PURPOSE_DECRYPT
                    | KeyProperties.PURPOSE_ENCRYPT;
            final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyName, purpose);
            // 需要用户验证方能取出
            builder.setUserAuthenticationRequired(true);
            builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
            builder.setEncryptionPaddings(
                    KeyProperties.ENCRYPTION_PADDING_PKCS7);
            generator.init(builder.build());
            generator.generateKey();
            result = true;
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return result;
    }

    public FingerprintManager.CryptoObject getCryptoObject(String keyName,
            int purpose, byte[] IV) throws FingerPrintInvalidException {
        try {
            mStore.load(null);
            final SecretKey key = (SecretKey) mStore.getKey(keyName, null);
            if (key == null) {
                generateKey(keyName);
            }
            final Cipher cipher = Cipher
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (purpose == KeyProperties.PURPOSE_ENCRYPT) {
                cipher.init(purpose, key);
            } else {
                cipher.init(purpose, key, new IvParameterSpec(IV));
            }
            return new FingerprintManager.CryptoObject(cipher);
        } catch (InvalidKeyException e) {
            throw new FingerPrintInvalidException("设备指纹库发生变化，请重新申请当前卡片的指纹验证权限");
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean isKeyProtectedEnforcedBySecureHardware() {
        try {
            // 这里随便生成一个key，检查是不是受保护即可
            generateKey("temp");
            final SecretKey key = (SecretKey) mStore.getKey("temp", null);
            if (key == null) {
                Log.e(TAG,
                        "isKeyProtectedEnforcedBySecureHardware:key is null");
                return false;
            }
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, KEY_STORE_TYPE);
            KeyInfo keyInfo;
            keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
            return keyInfo.isInsideSecureHardware() && keyInfo
                    .isUserAuthenticationRequirementEnforcedBySecureHardware();
        } catch (Exception e) {
            Log.e(TAG, e.getMessage());
            return false;
        }
    }
}
