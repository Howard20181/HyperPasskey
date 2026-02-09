package bridge;

import android.annotation.NonNull;
import android.app.Notification;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.os.UserHandle;
import android.service.notification.StatusBarNotification;

public class HiddenApiBridge {
    public static Context StatusBarNotification_getPackageContext(@NonNull StatusBarNotification sbn, @NonNull Context systenUiContext) {
        return sbn.getPackageContext(systenUiContext);
    }

    public static void Notification_setSmallIcon(Notification notification, Icon icon) {
        notification.setSmallIcon(icon);
    }

    public static Bitmap Icon_getBitmap(Icon icon) {
        return icon.getBitmap();
    }

    public static int Icon_getDataLength(Icon icon) {
        return icon.getDataLength();
    }

    public static int Icon_getDataOffset(Icon icon) {
        return icon.getDataOffset();
    }

    public static byte[] Icon_getDataBytes(Icon icon) {
        return icon.getDataBytes();
    }

    public static int Icon_getType(@NonNull Icon icon) {
        return icon.getType();
    }

    public static int Icon_getResId(Icon icon) {
        return icon.getResId();
    }

    public static Resources Icon_getResources(Icon icon) {
        return icon.getResources();
    }

    public static String Icon_getResPackage(Icon icon) {
        return icon.getResPackage();
    }

    public static String Icon_getUriString(Icon icon) {
        return icon.getUriString();
    }

    public static Uri Icon_getUri(Icon icon) {
        return icon.getUri();
    }

    public static int UserHandle_getIdentifier(UserHandle userHandle) {
        return userHandle.getIdentifier();
    }

    public static ApplicationInfo PackageManager_getApplicationInfoAsUser(PackageManager pm, String packageName,
                                                                          int flags, int userId) {
        return pm.getApplicationInfoAsUser(packageName, flags, userId);
    }

    public static Context Context_createApplicationContext(Context context, ApplicationInfo application,
                                                           int flags) {
        return context.createApplicationContext(application, flags);
    }
}
