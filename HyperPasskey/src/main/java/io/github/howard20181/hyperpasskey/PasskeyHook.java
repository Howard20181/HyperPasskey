package io.github.howard20181.hyperpasskey;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.credentials.CredentialManager;
import android.os.Build;
import android.credentials.selection.IntentCreationResult;
import android.os.CancellationSignal;
import android.service.credentials.CallingAppInfo;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.exceptions.NoResultException;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.query.matchers.MethodsMatcher;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;

import io.github.libxposed.api.XposedModule;

@SuppressLint({"PrivateApi", "BlockedPrivateApi", "SoonBlockedPrivateApi"})
public class PasskeyHook extends XposedModule {
    private static final String TAG = "HyperPasskey";
    private static final String settingsPackageName = "com.android.settings";
    private static final String securityCenterPackageName = "com.miui.securitycenter";
    private static final String xiaomiScannerPackageName = "com.xiaomi.scanner";
    private static XposedModule module;
    Class<?> cRequestSession;
    private static Field fIsInternationalBuildBoolean;
    private static Field fHybridService;
    private static boolean originalIsInternationalBuild;
    private final static Hooker isInternationalBuildHooker = new IsInternationalBuildHooker();

    @Override
    public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        module = this;
        System.loadLibrary("dexkit");
    }

    @Override
    public void onSystemServerStarting(@NonNull SystemServerStartingParam param) {
        var classLoader = param.getClassLoader();
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                try {
                    hookIntentFactory(classLoader);
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "hook IntentFactory failed", e);
                }
            }
            try {
                cRequestSession = classLoader.loadClass("com.android.server.credentials.RequestSession");
                fHybridService = cRequestSession.getDeclaredField("mHybridService");
                fHybridService.setAccessible(true);
                hookRequestSession(classLoader);
            } catch (Exception e) {
                log(Log.ERROR, TAG, "hook RequestSession failed", e);
            }
        } catch (
                Throwable tr) {
            log(Log.ERROR, TAG, "Error hooking system service", tr);
        }
    }

    @Override
    public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!param.isFirstPackage()) return;
        var classLoader = param.getClassLoader();
        var pn = param.getPackageName();
        try {
            var buildClass = classLoader.loadClass("miui.os.Build");
            fIsInternationalBuildBoolean = buildClass.getDeclaredField("IS_INTERNATIONAL_BUILD");
            fIsInternationalBuildBoolean.setAccessible(true);
            originalIsInternationalBuild = fIsInternationalBuildBoolean.getBoolean(null);
        } catch (Exception e) {
            log(Log.ERROR, TAG, "find IS_INTERNATIONAL_BUILD failed", e);
        }
        log(Log.DEBUG, TAG, "onPackageLoaded: " + pn);
        try (var bridge = DexKitBridge.create(classLoader, true)) {
            switch (pn) {
                case settingsPackageName -> {
                    try {
                        hookDefaultCombinedPicker(classLoader);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook DefaultCombinedPicker failed", e);
                    }
                    try {
                        hookDefaultCombinedPreferenceController(classLoader);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook DefaultCombinedPreferenceController failed", e);
                    }
                    try {
                        hookOnCombiPreferenceClickListener(classLoader, bridge);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook OnCombiPreferenceClickListener failed", e);
                    }
                    if (Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        try {
                            hookDefaultAppPreferenceController(classLoader);
                        } catch (Exception e) {
                            log(Log.ERROR, TAG, "hook DefaultAppPreferenceController failed", e);
                        }
                    }
                }
                case securityCenterPackageName -> {
                    try {
                        securityCenterApplicationHook(classLoader, bridge);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook SecurityCenterApplication failed", e);
                    }
                }
                case xiaomiScannerPackageName -> {
                    try {
                        hookMiFiDoBean(classLoader);
                    } catch (ClassNotFoundException e) {
                        log(Log.ERROR, TAG, "hook MiFiDoBean failed", e);
                    }
                }
            }
        }
    }

    private void hookMiFiDoBean(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.xiaomi.scanner.module.code.utils.bean.MiFiDoBean");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getAppPackageName");
                hook(aMethod).intercept(chain -> "");
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultCombinedPreferenceController(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPreferenceController");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getCombinedProviderInfos", CredentialManager.class, int.class);
                hook(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultAppPreferenceController(ClassLoader classLoader) throws ClassNotFoundException, NoSuchMethodException {
        var iClass = classLoader.loadClass("com.android.settings.applications.defaultapps.DefaultAppPreferenceController");
        var preferenceClass = classLoader.loadClass("androidx.preference.Preference");
        var aMethod = iClass.getDeclaredMethod("updateState", preferenceClass);
        hook(aMethod).intercept(isInternationalBuildHooker);
    }

    private void hookDefaultCombinedPicker(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPicker");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("setDefaultKey", String.class);
                hook(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookOnCombiPreferenceClickListener(ClassLoader classLoader, DexKitBridge bridge) {
        var onLeftSideClickedMatcher = MethodMatcher.create()
                .name("onLeftSideClicked")
                .paramCount(0)
                .addInvoke("Lcom/android/settings/applications/credentials/CombinedProviderInfo;->launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)V");
        bridge.findClass(FindClass.create()
                .searchPackages("com.android.settings.applications.credentials")
                .matcher(ClassMatcher.create().methods(MethodsMatcher.create().add(onLeftSideClickedMatcher)))
        ).findMethod(FindMethod.create().matcher(onLeftSideClickedMatcher)
        ).forEach(methodData -> {
            try {
                hook(methodData.getMethodInstance(classLoader)).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException e) {
                log(Log.ERROR, TAG, "hook onLeftSideClicked failed", e);
            }
        });
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
        hook(constructorRequestSession).intercept(chain -> {
            chain.proceed();
            if (fHybridService != null) {
                fHybridService.set(chain.getThisObject(), "com.google.android.gms/.auth.api.credentials.credman.service.RemoteService");
            }
            return null;
        });
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private void hookIntentFactory(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException {
        Method mGetOemOverrideComponentName;
        var classIntentFactory = classLoader.loadClass("android.credentials.selection.IntentFactory");
        var classIntentCreationResultBuilder = classLoader.loadClass("android.credentials.selection.IntentCreationResult$Builder");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            mGetOemOverrideComponentName = classIntentFactory.getDeclaredMethod("getOemOverrideComponentName",
                    Context.class, classIntentCreationResultBuilder, int.class);
        } else {
            mGetOemOverrideComponentName = classIntentFactory.getDeclaredMethod("getOemOverrideComponentName",
                    Context.class, classIntentCreationResultBuilder);
        }
        hook(mGetOemOverrideComponentName).intercept(chain -> {
            var args = chain.getArgs();
            if (args.size() >= 2 && args.get(0) instanceof Context context && args.get(1) instanceof IntentCreationResult.Builder intentResultBuilder) {
                final String oemComponentString = "com.google.android.gms/.identitycredentials.ui.CredentialChooserActivity";
                try {
                    var oemComponentName = ComponentName.unflattenFromString(oemComponentString);
                    if (oemComponentName != null) {
                        try {
                            var info = context.getPackageManager().getActivityInfo(oemComponentName,
                                    PackageManager.ComponentInfoFlags.of(PackageManager.MATCH_SYSTEM_ONLY));
                            boolean oemComponentEnabled = info.enabled;
                            int runtimeComponentEnabledState = context.getPackageManager()
                                    .getComponentEnabledSetting(oemComponentName);
                            if (runtimeComponentEnabledState
                                    == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
                                oemComponentEnabled = true;
                            } else if (runtimeComponentEnabledState
                                    == PackageManager.COMPONENT_ENABLED_STATE_DISABLED) {
                                oemComponentEnabled = false;
                            }
                            if (oemComponentEnabled && info.exported) {
                                intentResultBuilder.setOemUiPackageName(oemComponentName.getPackageName());
                                intentResultBuilder.setOemUiUsageStatus(IntentCreationResult
                                        .OemUiUsageStatus.SUCCESS);
                                return oemComponentName;
                            }
                        } catch (PackageManager.NameNotFoundException e) {
                            module.log(Log.ERROR, TAG, "Unable to find oem CredMan UI component: "
                                    + oemComponentString + ".", e);
                        }
                    }
                } catch (Exception e) {
                    module.log(Log.ERROR, TAG, "Failed to parse OEM component name "
                            + oemComponentString + ": " + e);
                }
            }
            return chain.proceed();
        });
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
                        )).single();
                var setStringResourceConfigIfNeedMethodInstance = mSetStringResourceConfigIfNeed.getMethodInstance(classLoader);
                deoptimize(setStringResourceConfigIfNeedMethodInstance);
                var mConfigForAutofillService = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class)
                                .addEqString("autofill_service")
                                .addInvoke(mSetStringResourceConfigIfNeed.getDescriptor())
                        )).single().getMethodInstance(classLoader);
                hook(mConfigForAutofillService).intercept(chain -> null);
            } catch (NoSuchMethodException | NoResultException e) {
                log(Log.WARN, TAG, "hook configForAutofillService", e);
            }
            try {
                var mSetStringArrayResourceConfigIfNeed = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class, String.class, int.class)
                                .addInvoke("Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;")
                                .addInvoke("Landroid/provider/Settings$Secure;->putString(Landroid/content/ContentResolver;Ljava/lang/String;Ljava/lang/String;)Z")
                        )).single();
                var setStringArrayResourceConfigIfNeedMethodInstance = mSetStringArrayResourceConfigIfNeed.getMethodInstance(classLoader);
                deoptimize(setStringArrayResourceConfigIfNeedMethodInstance);
                var mSetDefaultConfigForAutofillAndCredentialManager = cApplication.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .paramTypes(Context.class)
                                .usingEqStrings("credential_service", "credential_service_primary")
                                .addInvoke(mSetStringArrayResourceConfigIfNeed.getDescriptor())
                        )).single().getMethodInstance(classLoader);
                hook(mSetDefaultConfigForAutofillAndCredentialManager).intercept(chain -> null);
            } catch (NoSuchMethodException | NoResultException e) {
                log(Log.ERROR, TAG, "hook setDefaultConfigForAutofillAndCredentialManager", e);
            }
        }
    }

    private static class IsInternationalBuildHooker implements Hooker {

        @Nullable
        @Override
        public Object intercept(@NonNull Chain chain) throws Throwable {
            if (fIsInternationalBuildBoolean != null) {
                fIsInternationalBuildBoolean.setBoolean(null, true);
                var proceed = chain.proceed();
                fIsInternationalBuildBoolean.setBoolean(null, originalIsInternationalBuild);
                return proceed;
            }
            return chain.proceed();
        }
    }
}
