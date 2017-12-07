package com.vigorous.fingerprintchecker.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import com.vigorous.fingerprintchecker.R;
import com.vigorous.fingerprintchecker.exception.FingerPrintInvalidException;
import com.vigorous.fingerprintchecker.fingerprint.FingerPrintAuthenticationCallback;
import com.vigorous.fingerprintchecker.fingerprint.FingerprintHelper;
import com.vigorous.fingerprintchecker.utils.AndroidPermissionUtil;

public class MainActivity extends AppCompatActivity
        implements View.OnClickListener {

    private static final String finger_sp = "finger_sp";
    private static final String finger_result = "finger_result";
    private static final String finger_iv = "finger_iv";

    private static final String keyName = "keyName";
    private FingerprintHelper mFingerprintHelper;
    private TextView mTvResult;
    private Button mBtnFingerPrintEnvironmentCheck;
    private Button mBtnFingerPrintInput;
    private Button mBtnFingerPrintVerify;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mFingerprintHelper = FingerprintHelper.getInstance(this);
        initView();
    }

    private void initView() {
        mTvResult = (TextView) findViewById(R.id.tv_result);
        mTvResult.setMovementMethod(ScrollingMovementMethod.getInstance());
        mBtnFingerPrintEnvironmentCheck = (Button) findViewById(
                R.id.btn_fingerPrint_environment_check);
        mBtnFingerPrintEnvironmentCheck.setOnClickListener(this);
        mBtnFingerPrintInput = (Button) findViewById(
                R.id.btn_input_fingerPrint);
        mBtnFingerPrintInput.setOnClickListener(this);
        mBtnFingerPrintVerify = (Button) findViewById(
                R.id.btn_verify_fingerPrint);
        mBtnFingerPrintVerify.setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
        case R.id.btn_fingerPrint_environment_check:
            if (mFingerprintHelper != null) {
                int result = mFingerprintHelper.checkFingerprintAvailable();
                if (result == FingerprintHelper.FINGERPRINT_UNAVAILABLE) {
                    mTvResult.append("尚未录入指纹，请先录入。\n");
                } else if (result == FingerprintHelper.FINGERPRINT_AVAILABLE) {
                    // 当且仅当指纹模块可用时，去检测指纹权限并提示用户开启授权
                    mTvResult.append("指纹模块可正常使用。\n");
                    if (!AndroidPermissionUtil.checkPermission(this,
                            AndroidPermissionUtil.PERMISSION_FINGERPRINT)) {
                        AndroidPermissionUtil.requestPermission(this,
                                AndroidPermissionUtil.CODE_FINGERPRINT);
                    }
                } else {
                    mTvResult.append("抱歉，您当前设备不支持指纹检测。\n");
                }
            }
            break;
        case R.id.btn_input_fingerPrint:
            if (mFingerprintHelper != null) {
                // 首先生成keystore
                if (mFingerprintHelper.generateKey(keyName)) {
                    try {
                        // 使用已经在系统中录入的指纹进行秘钥生成，此时fingerToken与IV传入空串
                        mFingerprintHelper.authenticate(keyName,
                                FingerprintHelper.APPLY, "", "",
                                new FingerPrintAuthenticationCallback() {
                                    @Override
                                    public void onAuthenticationSucceeded(
                                            String result, int properties,
                                            String IV) {
                                        mTvResult.append("指纹录入成功！请保存result:"
                                                + result + "\n指纹认证向量IV：" + IV
                                                + "\n");

                                        // Store it anyway
                                        SharedPreferences sp = getSharedPreferences(
                                                finger_sp,
                                                Context.MODE_PRIVATE);
                                        SharedPreferences.Editor editor = sp
                                                .edit();
                                        editor.putString(finger_result, result);
                                        editor.putString(finger_iv, IV);
                                        editor.commit();
                                    }

                                    @Override
                                    public void onAuthenticationFail(
                                            String errorMsg) {
                                        mTvResult.append("抱歉，指纹录入失败\n");
                                    }

                                    @Override
                                    public void onAuthenticationOverLimit(
                                            String errorMsg) {
                                        mTvResult.append("抱歉，指纹录入尝试次数超限\n");
                                    }
                                });
                    } catch (FingerPrintInvalidException e) {
                        e.printStackTrace();
                        mTvResult.append("抱歉，指纹录入失败\n");
                    }
                } else {
                    mTvResult.append("抱歉，生成秘钥失败。\n");
                }
            }
            break;
        case R.id.btn_verify_fingerPrint:
            if (mFingerprintHelper != null) {
                SharedPreferences sp = getSharedPreferences(finger_sp,
                        Context.MODE_PRIVATE);
                String token = sp.getString(finger_result, "");
                String iv = sp.getString(finger_iv, "");
                if (TextUtils.isEmpty(token) || TextUtils.isEmpty(iv)) {
                    mTvResult.append("您的指纹尚未录入，请确认后再尝试认证！\n");
                    break;
                }
                try {
                    mFingerprintHelper.authenticate(keyName,
                            FingerprintHelper.VERIFY, token, iv,
                            new FingerPrintAuthenticationCallback() {
                                @Override
                                public void onAuthenticationSucceeded(
                                        String result, int properties,
                                        String IV) {
                                    mTvResult.append("指纹认证成功！\n");
                                }

                                @Override
                                public void onAuthenticationFail(
                                        String errorMsg) {
                                    mTvResult.append("指纹认证失败！\n");
                                }

                                @Override
                                public void onAuthenticationOverLimit(
                                        String errorMsg) {
                                    mTvResult.append("指纹认证超限！\n");
                                }
                            });
                } catch (FingerPrintInvalidException e) {
                    e.printStackTrace();
                }
            }
            break;
        default:
            break;
        }
    }
}
