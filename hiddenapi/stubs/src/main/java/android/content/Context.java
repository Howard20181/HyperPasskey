package android.content;

import android.content.pm.ApplicationInfo;

public abstract class Context {
    public Context createApplicationContext(ApplicationInfo application,
                                            int flags) {
        throw new UnsupportedOperationException("STUB");
    }
}
