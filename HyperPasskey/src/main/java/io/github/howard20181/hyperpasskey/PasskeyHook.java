package io.github.howard20181.hyperpasskey;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.credentials.CredentialManager;
import android.os.Build;
import android.credentials.selection.IntentCreationResult;

import androidx.annotation.NonNull;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.annotations.AfterInvocation;
import io.github.libxposed.api.annotations.BeforeInvocation;
import io.github.libxposed.api.annotations.XposedHooker;

@SuppressLint({"PrivateApi", "BlockedPrivateApi", "SoonBlockedPrivateApi"})
public class PasskeyHook extends XposedModule {
    private static final String settingsPackageName = "com.android.settings";
    private static final String securityCenterPackageName = "com.miui.securitycenter";
    private static XposedModule module;
    private static Field fIsInternationalBuildBoolean;
    private static boolean originalIsInternationalBuild;

    static {
        System.loadLibrary("dexkit");
    }

    public PasskeyHook(XposedInterface base, ModuleLoadedParam param) {
        super(base, param);
        module = this;
    }

    @Override
    public void onSystemServerLoaded(@NonNull SystemServerLoadedParam param) {
        var classLoader = param.getClassLoader();
        try {
            try {
                hookIntentFactory(classLoader);
            } catch (Exception e) {
                log("hook IntentFactory failed", e);
            }
        } catch (Throwable tr) {
            log("Error hooking system service", tr);
        }
    }

    @Override
    public void onPackageLoaded(@NonNull PackageLoadedParam param) {
        if (!param.isFirstPackage()) return;
        var classLoader = param.getClassLoader();
        var pn = param.getPackageName();
        try {
            var buildClass = classLoader.loadClass("miui.os.Build");
            fIsInternationalBuildBoolean = buildClass.getDeclaredField("IS_INTERNATIONAL_BUILD");
            fIsInternationalBuildBoolean.setAccessible(true);
            originalIsInternationalBuild = fIsInternationalBuildBoolean.getBoolean(null);
        } catch (Exception e) {
            log("find IS_INTERNATIONAL_BUILD failed", e);
        }
        if (pn.equals(settingsPackageName)) {
            try {
                hookDefaultCombinedPicker(classLoader);
            } catch (Exception e) {
                log("hook DefaultCombinedPicker failed", e);
            }
            try {
                hookDefaultCombinedPreferenceController(classLoader);
            } catch (Exception e) {
                log("hook DefaultCombinedPreferenceController failed", e);
            }
        } else if (pn.equals(securityCenterPackageName)) {
            try (var bridge = DexKitBridge.create(classLoader, true)) {
                securityCenterApplicationHook(classLoader, bridge);
            }
        }
    }

    private void hookDefaultCombinedPreferenceController(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPreferenceController");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getCombinedProviderInfos", CredentialManager.class, int.class);
                hook(aMethod, IsInternationalBuildHooker.class);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultCombinedPicker(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPicker");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("setDefaultKey", String.class);
                hook(aMethod, IsInternationalBuildHooker.class);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookIntentFactory(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException {
        var iClass = classLoader.loadClass("android.credentials.selection.IntentFactory");
        var aClass = classLoader.loadClass("android.credentials.selection.IntentCreationResult$Builder");
        Method mGetOemOverrideComponentName;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            mGetOemOverrideComponentName = iClass.getDeclaredMethod("getOemOverrideComponentName", Context.class, aClass, int.class);
        } else {
            mGetOemOverrideComponentName = iClass.getDeclaredMethod("getOemOverrideComponentName", Context.class, aClass);
        }
        hook(mGetOemOverrideComponentName, GetOemOverrideComponentNameHooker.class);
    }


    private void securityCenterApplicationHook(ClassLoader classLoader, DexKitBridge bridge) {
        var cApplication = bridge.getClassData("Lcom/miui/securitycenter/Application;");
        if (cApplication != null) {
            try {
                var mSetStringResourceConfigIfNeed = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class, String.class, int.class)
                                .addInvoke("Landroid/content/res/Resources;->getString(I)Ljava/lang/String;")
                                .addInvoke("Landroid/provider/Settings$Secure;->putString(Landroid/content/ContentResolver;Ljava/lang/String;Ljava/lang/String;)Z")
                        )
                ).single();
                var setStringResourceConfigIfNeedMethodInstance = mSetStringResourceConfigIfNeed.getMethodInstance(classLoader);
                deoptimize(setStringResourceConfigIfNeedMethodInstance);
                var mConfigForAutofillService = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class)
                                .addEqString("autofill_service")
                                .addInvoke(mSetStringResourceConfigIfNeed.getDescriptor())
                        )
                ).single().getMethodInstance(classLoader);
                hook(mConfigForAutofillService, ReturnSkipHooker.class);
            } catch (NoSuchMethodException e) {
                module.log("hook configForAutofillService", e);
            }
            try {
                var mSetStringArrayResourceConfigIfNeed = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class, String.class, int.class)
                                .addInvoke("Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;")
                                .addInvoke("Landroid/provider/Settings$Secure;->putString(Landroid/content/ContentResolver;Ljava/lang/String;Ljava/lang/String;)Z")
                        )
                ).single();
                var setStringArrayResourceConfigIfNeedMethodInstance = mSetStringArrayResourceConfigIfNeed.getMethodInstance(classLoader);
                deoptimize(setStringArrayResourceConfigIfNeedMethodInstance);
                var mSetDefaultConfigForAutofillAndCredentialManager = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class)
                                .usingEqStrings("credential_service", "credential_service_primary")
                                .addInvoke(mSetStringArrayResourceConfigIfNeed.getDescriptor())
                        )
                ).single().getMethodInstance(classLoader);
                hook(mSetDefaultConfigForAutofillAndCredentialManager, ReturnSkipHooker.class);
            } catch (NoSuchMethodException e) {
                module.log("hook setDefaultConfigForAutofillAndCredentialManager", e);
            }
        }
    }

    @XposedHooker
    private static class ReturnSkipHooker implements Hooker {
        @BeforeInvocation
        public static void before(@NonNull BeforeHookCallback callback) {
            callback.returnAndSkip(null);
        }
    }

    @XposedHooker
    private static class GetOemOverrideComponentNameHooker implements Hooker {
        @BeforeInvocation
        public static void before(@NonNull BeforeHookCallback callback) {
            var args = callback.getArgs();
            var context = (Context) args[0];
            var intentResultBuilder = (IntentCreationResult.Builder) args[1];
            ComponentName result = null;
            String oemComponentString = "com.google.android.gms/.identitycredentials.ui.CredentialChooserActivity";
            ComponentName oemComponentName = null;
            try {
                oemComponentName = ComponentName.unflattenFromString(oemComponentString);
            } catch (Exception e) {
                module.log("Failed to parse OEM component name " + oemComponentString + ": " + e);
            }
            if (oemComponentName != null) {
                try {
                    intentResultBuilder.setOemUiPackageName(oemComponentName.getPackageName());
                    ActivityInfo info = context.getPackageManager().getActivityInfo(
                            oemComponentName,
                            PackageManager.ComponentInfoFlags.of(PackageManager.MATCH_SYSTEM_ONLY));
                    boolean oemComponentEnabled = info.enabled;
                    int runtimeComponentEnabledState = context.getPackageManager().getComponentEnabledSetting(oemComponentName);
                    if (runtimeComponentEnabledState == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
                        oemComponentEnabled = true;
                    } else if (runtimeComponentEnabledState == PackageManager.COMPONENT_ENABLED_STATE_DISABLED) {
                        oemComponentEnabled = false;
                    }
                    if (oemComponentEnabled && info.exported) {
                        intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.SUCCESS);
                        module.log("Found enabled oem CredMan UI component." + oemComponentString);
                        result = oemComponentName;
                    } else {
                        intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_FOUND_BUT_NOT_ENABLED);
                        module.log("Found enabled oem CredMan UI component but it was not " + "enabled.");
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_BUT_NOT_FOUND);
                    module.log("Unable to find oem CredMan UI component: " + oemComponentString + ".");
                }
            } else {
                intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_BUT_NOT_FOUND);
                module.log("Invalid OEM ComponentName format.");
            }
            callback.returnAndSkip(result);
        }
    }

    @XposedHooker
    private static class IsInternationalBuildHooker implements Hooker {
        @BeforeInvocation
        public static void before(@NonNull BeforeHookCallback callback) throws IllegalAccessException {
            if (fIsInternationalBuildBoolean != null) {
                fIsInternationalBuildBoolean.setBoolean(null, true);
            }
        }

        @AfterInvocation
        public static void after(@NonNull AfterHookCallback callback) throws IllegalAccessException {
            if (fIsInternationalBuildBoolean != null) {
                fIsInternationalBuildBoolean.setBoolean(null, originalIsInternationalBuild);
            }
        }
    }
}
