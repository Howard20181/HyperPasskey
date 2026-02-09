package android.credentials.selection;

import android.annotation.NonNull;
import android.annotation.Nullable;

public class IntentCreationResult {
    public enum OemUiUsageStatus {
        UNKNOWN,
        // Success: the UI specified in config_oemCredentialManagerDialogComponent was used to
        // fulfill the request.
        SUCCESS,
        // The config value was not specified (e.g. left empty).
        OEM_UI_CONFIG_NOT_SPECIFIED,
        // The config value component was specified but not found (e.g. component doesn't exist or
        // component isn't a system app).
        OEM_UI_CONFIG_SPECIFIED_BUT_NOT_FOUND,
        // The config value component was found but not enabled.
        OEM_UI_CONFIG_SPECIFIED_FOUND_BUT_NOT_ENABLED,
    }

    public static final class Builder {
        @NonNull
        public Builder setOemUiPackageName(@Nullable String oemUiPackageName) {
            throw new UnsupportedOperationException("STUB");
        }

        @NonNull
        public Builder setOemUiUsageStatus(OemUiUsageStatus oemUiUsageStatus) {
            throw new UnsupportedOperationException("STUB");
        }
    }
}
