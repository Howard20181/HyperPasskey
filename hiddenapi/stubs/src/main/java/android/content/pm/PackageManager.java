package android.content.pm;

import android.annotation.NonNull;

public class PackageManager {
    @NonNull
    public ApplicationInfo getApplicationInfoAsUser(@NonNull String packageName,
                                                    int flags, int userId) {
        throw new UnsupportedOperationException("STUB");
    }
}
