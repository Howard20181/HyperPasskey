package io.github.howard20181.hyperpasskey;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.credentials.CredentialManager;
import android.os.Build;
import android.credentials.selection.IntentCreationResult;
import android.os.CancellationSignal;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.service.credentials.CallingAppInfo;

import androidx.annotation.NonNull;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Set;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.annotations.AfterInvocation;
import io.github.libxposed.api.annotations.BeforeInvocation;
import io.github.libxposed.api.annotations.XposedHooker;

@SuppressLint({"PrivateApi", "BlockedPrivateApi", "SoonBlockedPrivateApi"})
public class PasskeyHook extends XposedModule {
    private static final String settingsPackageName = "com.android.settings";
    private static final String securityCenterPackageName = "com.miui.securitycenter";
    private static final String xiaomiScannerPackageName = "com.xiaomi.scanner";
    private static XposedModule module;
    Class<?> cRequestSession;
    private static Field fIsInternationalBuildBoolean;
    private static Field fHybridService;
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
            try {
                cRequestSession = classLoader.loadClass("com.android.server.credentials.RequestSession");
                fHybridService = cRequestSession.getDeclaredField("mHybridService");
                fHybridService.setAccessible(true);
                hookRequestSession(classLoader);
            } catch (Exception e) {
                log("hook RequestSession failed", e);
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
        switch (pn) {
            case settingsPackageName -> {
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
                if (Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    try {
                        hookDefaultAppPreferenceController(classLoader);
                    } catch (Exception e) {
                        log("hook DefaultAppPreferenceController failed", e);
                    }
                }
            }
            case securityCenterPackageName -> {
                try (var bridge = DexKitBridge.create(classLoader, true)) {
                    securityCenterApplicationHook(classLoader, bridge);
                }
            }
            case xiaomiScannerPackageName -> {
                try {
                    hookMiFiDoBean(classLoader);
                } catch (ClassNotFoundException e) {
                    log("hook MiFiDoBean failed", e);
                }
            }
        }
    }

    private void hookMiFiDoBean(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.xiaomi.scanner.module.code.utils.bean.MiFiDoBean");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getAppPackageName");
                hook(aMethod, GetAppPackageNameHooker.class);
            } catch (NoSuchMethodException ignored) {
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

    private void hookDefaultAppPreferenceController(ClassLoader classLoader) throws ClassNotFoundException, NoSuchMethodException {
        var iClass = classLoader.loadClass("com.android.settings.applications.defaultapps.DefaultAppPreferenceController");
        var PreferenceClass = classLoader.loadClass("androidx.preference.Preference");
        var aMethod = iClass.getDeclaredMethod("updateState", PreferenceClass);
        hook(aMethod, IsInternationalBuildHooker.class);
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

    private void hookRequestSession(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException {
        var aClass = classLoader.loadClass("com.android.server.credentials.RequestSession$SessionLifetime");
        Constructor<?> constructorRequestSession;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            constructorRequestSession = cRequestSession.getDeclaredConstructor(Context.class, aClass,
                    Object.class, int.class, int.class, Object.class, Object.class, String.class,
                    CallingAppInfo.class, Set.class, CancellationSignal.class, long.class, boolean.class);
        } else {
            constructorRequestSession = cRequestSession.getDeclaredConstructor(Context.class, aClass,
                    Object.class, int.class, int.class, Object.class, Object.class, String.class,
                    CallingAppInfo.class, Set.class, CancellationSignal.class, long.class);
        }
        hook(constructorRequestSession, RequestSessionHooker.class);
    }

    private void hookIntentFactory(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException {
        Class<?> classIntentFactory;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            Method mGetOemOverrideComponentName;
            classIntentFactory = classLoader.loadClass("android.credentials.selection.IntentFactory");
            var classIntentCreationResultBuilder = classLoader.loadClass("android.credentials.selection.IntentCreationResult$Builder");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
                mGetOemOverrideComponentName = classIntentFactory.getDeclaredMethod("getOemOverrideComponentName", Context.class, classIntentCreationResultBuilder, int.class);
            } else {
                mGetOemOverrideComponentName = classIntentFactory.getDeclaredMethod("getOemOverrideComponentName", Context.class, classIntentCreationResultBuilder);
            }
            hook(mGetOemOverrideComponentName, GetOemOverrideComponentNameHooker.class);
        } else {
            classIntentFactory = classLoader.loadClass("android.credentials.ui.IntentFactory");
            var classRequestInfo = classLoader.loadClass("android.credentials.ui.RequestInfo");
            var mCreateCredentialSelectorIntent = classIntentFactory.getDeclaredMethod("createCredentialSelectorIntent", classRequestInfo, ArrayList.class, ArrayList.class, ResultReceiver.class);
            var mCreateCancelUiIntent = classIntentFactory.getDeclaredMethod("createCancelUiIntent", IBinder.class, boolean.class, String.class);
            hook(mCreateCredentialSelectorIntent, GetOemOverrideComponentNameHooker.class);
            hook(mCreateCancelUiIntent, GetOemOverrideComponentNameHooker.class);
        }
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
    private static class GetAppPackageNameHooker implements Hooker {
        @BeforeInvocation
        public static void before(@NonNull BeforeHookCallback callback) {
            callback.returnAndSkip("");
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
    private static class RequestSessionHooker implements Hooker {
        @AfterInvocation
        public static void after(@NonNull AfterHookCallback callback) throws IllegalAccessException {
            if (fHybridService != null) {
                fHybridService.set(callback.getThisObject(), "com.google.android.gms/.auth.api.credentials.credman.service.RemoteService");
            }
        }
    }

    private static ComponentName getOemComponentName() {
        ComponentName oemComponentName = null;
        try {
            oemComponentName = ComponentName.unflattenFromString(GetOemOverrideComponentNameHooker.oemComponentString);
        } catch (Exception e) {
            module.log("Failed to parse OEM component name " + GetOemOverrideComponentNameHooker.oemComponentString + ": " + e);
        }
        return oemComponentName;
    }

    @XposedHooker
    private static class GetOemOverrideComponentNameHooker implements Hooker {
        private static final String oemComponentString = "com.google.android.gms/.identitycredentials.ui.CredentialChooserActivity";

        @BeforeInvocation
        public static void before(@NonNull BeforeHookCallback callback) {
            var args = callback.getArgs();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && args.length >= 2 && args[0] instanceof Context context && args[1] instanceof IntentCreationResult.Builder intentResultBuilder) {
                ComponentName oemComponentName = getOemComponentName();
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
                            callback.returnAndSkip(oemComponentName);
                        } else {
                            intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_FOUND_BUT_NOT_ENABLED);
                        }
                    } catch (PackageManager.NameNotFoundException e) {
                        intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_BUT_NOT_FOUND);
                        module.log("Unable to find oem CredMan UI component: " + oemComponentString + ".");
                    }
                } else {
                    intentResultBuilder.setOemUiUsageStatus(IntentCreationResult.OemUiUsageStatus.OEM_UI_CONFIG_SPECIFIED_BUT_NOT_FOUND);
                    module.log("Invalid OEM ComponentName format.");
                }
            }
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
