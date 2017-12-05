package com.vigorous.fingerprintchecker.utils;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Build;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AlertDialog;
import com.vigorous.fingerprintchecker.R;

/**
 * Created by vigorous.liang on 2017/11/30.
 */
public class AndroidPermissionUtil {

    private static final String TAG = AndroidPermissionUtil.class
            .getSimpleName();

    public static final int CODE_READ_PHONE_STATE = 0;
    public static final int CODE_ACCESS_FINE_LOCATION = CODE_READ_PHONE_STATE
            + 1;
    public static final int CODE_ACCESS_COARSE_LOCATION = CODE_ACCESS_FINE_LOCATION
            + 1;
    public static final int CODE_READ_EXTERNAL_STORAGE = CODE_ACCESS_COARSE_LOCATION
            + 1;
    public static final int CODE_WRITE_EXTERNAL_STORAGE = CODE_READ_EXTERNAL_STORAGE
            + 1;
    public static final int CODE_READ_CONTACTS = CODE_WRITE_EXTERNAL_STORAGE
            + 1;
    public static final int CODE_CAMERA = CODE_READ_CONTACTS + 1;
    public static final int CODE_FINGERPRINT = CODE_CAMERA + 1;

    public static final int CODE_MULTI_PERMISSION = 100;

    public static final String PERMISSION_READ_PHONE_STATE = Manifest.permission.READ_PHONE_STATE;
    public static final String PERMISSION_ACCESS_FINE_LOCATION = Manifest.permission.ACCESS_FINE_LOCATION;
    public static final String PERMISSION_ACCESS_COARSE_LOCATION = Manifest.permission.ACCESS_COARSE_LOCATION;
    public static final String PERMISSION_READ_EXTERNAL_STORAGE = Manifest.permission.READ_EXTERNAL_STORAGE;
    public static final String PERMISSION_WRITE_EXTERNAL_STORAGE = Manifest.permission.WRITE_EXTERNAL_STORAGE;
    public static final String PERMISSION_READ_CONTACTS = Manifest.permission.READ_CONTACTS;
    public static final String PERMISSION_CAMERA = Manifest.permission.CAMERA;
    public static final String PERMISSION_FINGERPRINT = Manifest.permission.USE_FINGERPRINT;

    private static final String[] requestPermissions = {
            PERMISSION_READ_PHONE_STATE, PERMISSION_ACCESS_FINE_LOCATION,
            PERMISSION_ACCESS_COARSE_LOCATION, PERMISSION_READ_EXTERNAL_STORAGE,
            PERMISSION_WRITE_EXTERNAL_STORAGE, PERMISSION_READ_CONTACTS,
            PERMISSION_CAMERA, PERMISSION_FINGERPRINT };

    /**
     * checkPermission
     *
     * @param activity
     * @param requestCode
     * @return
     */
    public static boolean checkPermission(final Context activity,
            final int requestCode) {
        if (activity == null) {
            return false;
        }

        if (requestCode < 0 || requestCode >= requestPermissions.length) {
            return false;
        }

        final String requestPermission = requestPermissions[requestCode];
        return checkPermission(activity, requestPermission);
    }

    /**
     * checkPermission
     *
     * @param context
     * @param requestPermission
     * @return
     */

    public static boolean checkPermission(final Context context,
            final String requestPermission) {
        if (context == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 23) {
            return true;
        }
        int checkSelfPermission;
        try {
            checkSelfPermission = ActivityCompat.checkSelfPermission(context,
                    requestPermission);
        } catch (RuntimeException e) {
            e.printStackTrace();
            return false;
        }
        if (checkSelfPermission != PackageManager.PERMISSION_GRANTED) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Requests permission.
     *
     * @param activity
     * @param requestCode request code, e.g. if you need request CAMERA
     *            permission,parameters is PermissionUtils.CODE_CAMERA
     */
    public static void requestPermission(final Activity activity,
            final int requestCode) {
        if (activity == null) {
            return;
        }
        if (requestCode < 0 || requestCode >= requestPermissions.length) {
            return;
        }
        final String requestPermission = requestPermissions[requestCode];
        int checkSelfPermission;
        try {
            checkSelfPermission = ActivityCompat.checkSelfPermission(activity,
                    requestPermission);
        } catch (RuntimeException e) {
            e.printStackTrace();
            return;
        }
        if (checkSelfPermission != PackageManager.PERMISSION_GRANTED) {
            if (ActivityCompat.shouldShowRequestPermissionRationale(activity,
                    requestPermission)) {
                shouldShowRationale(activity, requestCode, requestPermission);
            } else {
                ActivityCompat.requestPermissions(activity,
                        new String[] { requestPermission }, requestCode);
            }
        }
    }

    private static void shouldShowRationale(final Activity activity,
            final int requestCode, final String requestPermission) {
        String[] permissionsHint = activity.getResources()
                .getStringArray(R.array.permission_alert_info);
        showMessageOKCancel(activity, permissionsHint[requestCode],
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        ActivityCompat.requestPermissions(activity,
                                new String[] { requestPermission },
                                requestCode);
                    }
                });
    }

    private static void showMessageOKCancel(final Activity context,
            String message, DialogInterface.OnClickListener okListener) {
        new AlertDialog.Builder(context).setMessage(message)
                .setPositiveButton("AGREE", okListener)
                .setNegativeButton("Cancel", null).create().show();

    }

}