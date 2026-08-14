package io.github.howard20181.hyperpasskey;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
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

import org.luckypray.dexkit.DexKitCacheBridge;
import org.luckypray.dexkit.exceptions.NoResultException;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.ClassData;

import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import io.github.libxposed.api.XposedModule;

@SuppressLint({"PrivateApi", "BlockedPrivateApi", "SoonBlockedPrivateApi"})
public class PasskeyHook extends XposedModule {
    private static final String TAG = "HyperPasskey";
    private static final String settingsPackageName = "com.android.settings";
    private static final String securityCenterPackageName = "com.miui.securitycenter";
    private static final String xiaomiScannerPackageName = "com.xiaomi.scanner";
    private static Field fIsInternationalBuildBoolean;
    private final static Hooker isInternationalBuildHooker = new IsInternationalBuildHooker();
    private Object[] param;
    private static final int PARAM_PACKAGE_NAME = 0;
    private static final int PARAM_CLASS_LOADER = 1;
    private static final int PARAM_VERSION_NAME = 2;
    private static final int PARAM_VERSION_CODE = 3;
    private final Set<String> hookedIds = new HashSet<>();
    private DexKitCacheBridge.RecyclableBridge bridge;

    private HookBuilder hookE(Executable executable) {
        var builder = hook(executable);

        if (getApiVersion() >= 102) {
            var id = executable.toGenericString();
            builder.setId(id);
            hookedIds.add(id);
        }

        return builder;
    }

    @Override
    public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        System.loadLibrary("dexkit");
    }

    @Override
    public void onSystemServerStarting(@NonNull SystemServerStartingParam param) {
        var classLoader = param.getClassLoader();
        this.param = new Object[]{
                "system",
                classLoader,
                "",
                (long) 0
        };
        hookSystemServer(classLoader);
    }

    private void hookSystemServer(ClassLoader classLoader) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                try {
                    hookIntentFactory(classLoader);
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "hook IntentFactory failed", e);
                }
            }
            try {
                hookRequestSession(classLoader);
            } catch (Exception e) {
                log(Log.ERROR, TAG, "hook RequestSession failed", e);
            }
        } catch (Throwable tr) {
            log(Log.ERROR, TAG, "Error hooking system service", tr);
        }
    }

    @Override
    public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!param.isFirstPackage()) return;
        var classLoader = param.getClassLoader();
        var packageName = param.getPackageName();
        var pm = ActivityThread.currentApplication().getPackageManager();
        try {
            var buildClass = classLoader.loadClass("miui.os.Build");
            fIsInternationalBuildBoolean = buildClass.getDeclaredField("IS_INTERNATIONAL_BUILD");
            fIsInternationalBuildBoolean.setAccessible(true);
        } catch (Exception e) {
            log(Log.ERROR, TAG, "find IS_INTERNATIONAL_BUILD failed", e);
        }
        DexKitCacheBridge.init(MemoryCache.INSTANCE);
        long versionCode = 0;
        String versionName = "";
        try {
            var info = pm.getPackageInfo(packageName, 0);
            versionCode = info.getLongVersionCode();
            versionName = info.versionName;
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        var appTag = packageName + ":" + versionName + "-" + versionCode;
        this.param = new Object[]{
                packageName,
                classLoader,
                versionName,
                versionCode
        };
        log(Log.DEBUG, TAG, "create DexKitCacheBridge for " + appTag);
        try (var bridge = DexKitCacheBridge.create(appTag, classLoader)) {
            hookPackage(packageName, classLoader, bridge);
            this.bridge = bridge;
        }
    }

    private void hookPackage(String packageName, ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        switch (packageName) {
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
                    securityCenterApplicationhookE(classLoader, bridge);
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

    @Override
    public boolean onHotReloading(@NonNull HotReloadingParam param) {
        param.setSavedInstanceState(this.param);
        this.bridge.destroy();
        return true;
    }

    @Override
    public void onHotReloaded(@NonNull HotReloadedParam param) {
        var isSystemServer = param.isSystemServer();
        if (param.getSavedInstanceState() instanceof Object[] outState
                && outState[PARAM_PACKAGE_NAME] instanceof String packageName
                && outState[PARAM_CLASS_LOADER] instanceof ClassLoader classLoader
                && outState[PARAM_VERSION_NAME] instanceof String versionName
                && outState[PARAM_VERSION_CODE] instanceof Long versionCode) {
            this.param = new Object[]{
                    packageName,
                    classLoader,
                    versionName,
                    versionCode
            };
            try {
                if (isSystemServer) {
                    hookSystemServer(classLoader);
                } else {
                    var appTag = packageName + ":" + versionName + "-" + versionCode;
                    log(Log.DEBUG, TAG, "create DexKitCacheBridge for " + appTag);
                    try (var bridge = DexKitCacheBridge.create(appTag, classLoader)) {
                        hookPackage(packageName, classLoader, bridge);
                        this.bridge = bridge;
                    }
                }
            } catch (Throwable tr) {
                log(Log.ERROR, TAG, "Hot reload failed", tr);
            }
        }
        param.getOldHookHandles().forEach(h -> {
            if (!hookedIds.contains(h.getId())) {
                h.unhook();
            }
        });
    }

    private void hookMiFiDoBean(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.xiaomi.scanner.module.code.utils.bean.MiFiDoBean");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getAppPackageName");
                hookE(aMethod).intercept(chain -> "");
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultCombinedPreferenceController(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPreferenceController");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getCombinedProviderInfos", CredentialManager.class, int.class);
                hookE(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultAppPreferenceController(ClassLoader classLoader) throws ClassNotFoundException, NoSuchMethodException {
        var iClass = classLoader.loadClass("com.android.settings.applications.defaultapps.DefaultAppPreferenceController");
        var preferenceClass = classLoader.loadClass("androidx.preference.Preference");
        var aMethod = iClass.getDeclaredMethod("updateState", preferenceClass);
        hookE(aMethod).intercept(isInternationalBuildHooker);
    }

    private void hookDefaultCombinedPicker(ClassLoader classLoader) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPicker");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("setDefaultKey", String.class);
                hookE(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookOnCombiPreferenceClickListener(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        var onLeftSideClickedMatcher = MethodMatcher.create()
                .name("onLeftSideClicked")
                .paramCount(0)
                .addInvoke("Lcom/android/settings/applications/credentials/CombinedProviderInfo;->launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)V");
        bridge.getMethods(FindMethod.create()
                .searchPackages("com.android.settings.applications.credentials")
                .matcher(onLeftSideClickedMatcher)
        ).forEach(methodData -> {
            try {
                hookE(methodData.getMethodInstance(classLoader)).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException e) {
                log(Log.ERROR, TAG, "hook onLeftSideClicked failed", e);
            }
        });
    }

    private void hookRequestSession(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException, NoSuchFieldException {
        var cRequestSession = classLoader.loadClass("com.android.server.credentials.RequestSession");
        var fHybridService = cRequestSession.getDeclaredField("mHybridService");
        fHybridService.setAccessible(true);
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
        hookE(constructorRequestSession).intercept(chain -> {
            chain.proceed();
            fHybridService.set(chain.getThisObject(), "com.google.android.gms/.auth.api.credentials.credman.service.RemoteService");
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
        hookE(mGetOemOverrideComponentName).intercept(chain -> {
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
                            log(Log.ERROR, TAG, "Unable to find oem CredMan UI component: "
                                    + oemComponentString + ".", e);
                        }
                    }
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "Failed to parse OEM component name "
                            + oemComponentString + ": " + e);
                }
            }
            return chain.proceed();
        });
    }


    private void securityCenterApplicationhookE(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        var classDataList = new ArrayList<ClassData>();
        bridge.withBridge(rawBridge -> {
            var classData = rawBridge.getClassData("Lcom/miui/securitycenter/Application;");
            if (classData != null)
                classDataList.add(classData);
            classData = rawBridge.getClassData("Lcom/miui/securitycenter/service/CacheService;");
            if (classData != null)
                classDataList.add(classData);
        });
        try {
            var mSetStringResourceConfigIfNeed = bridge.getMethod(FindMethod.create()
                    .searchInClass(classDataList)
                    .matcher(MethodMatcher.create()
                            .addParamType(String.class)
                            .addParamType(int.class)
                            .addInvoke("Landroid/content/res/Resources;->getString(I)Ljava/lang/String;")
                            .addInvoke("Landroid/provider/Settings$Secure;->putString(Landroid/content/ContentResolver;Ljava/lang/String;Ljava/lang/String;)Z")
                    ));
            var setStringResourceConfigIfNeedMethodInstance = mSetStringResourceConfigIfNeed.getMethodInstance(classLoader);
            deoptimize(setStringResourceConfigIfNeedMethodInstance);
            var mConfigForAutofillService = bridge.getMethod(FindMethod.create()
                    .searchInClass(classDataList)
                    .matcher(MethodMatcher.create()
                            .addEqString("autofill_service")
                            .addInvoke(mSetStringResourceConfigIfNeed.toString())
                    )).getMethodInstance(classLoader);
            hookE(mConfigForAutofillService).intercept(chain -> null);
        } catch (NoSuchMethodException e) {
            log(Log.WARN, TAG, "hook configForAutofillService", e);
        } catch (NoResultException ignore) {
        }
        try {
            var mSetStringArrayResourceConfigIfNeed = bridge.getMethod(FindMethod.create()
                    .searchInClass(classDataList)
                    .matcher(MethodMatcher.create()
                            .addParamType(String.class)
                            .addParamType(int.class)
                            .addInvoke("Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;")
                            .addInvoke("Landroid/provider/Settings$Secure;->putString(Landroid/content/ContentResolver;Ljava/lang/String;Ljava/lang/String;)Z")
                    ));
            var setStringArrayResourceConfigIfNeedMethodInstance = mSetStringArrayResourceConfigIfNeed.getMethodInstance(classLoader);
            deoptimize(setStringArrayResourceConfigIfNeedMethodInstance);
            var mSetDefaultConfigForAutofillAndCredentialManager = bridge.getMethod(FindMethod.create()
                    .searchInClass(classDataList)
                    .matcher(MethodMatcher.create()
                            .usingEqStrings("credential_service", "credential_service_primary")
                            .addInvoke(mSetStringArrayResourceConfigIfNeed.toString())
                    )).getMethodInstance(classLoader);
            hookE(mSetDefaultConfigForAutofillAndCredentialManager).intercept(chain -> null);
        } catch (NoSuchMethodException e) {
            log(Log.ERROR, TAG, "hook setDefaultConfigForAutofillAndCredentialManager", e);
        } catch (NoResultException ignore) {
        }
    }

    private static class IsInternationalBuildHooker implements Hooker {
        private static final ReentrantLock INTL_LOCK = new ReentrantLock(true); // fair optional
        private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);
        private static final ThreadLocal<Boolean> PREV_VALUE = new ThreadLocal<>();

        @Nullable
        @Override
        public Object intercept(@NonNull Chain chain) throws Throwable {
            if (fIsInternationalBuildBoolean == null) return chain.proceed();
            INTL_LOCK.lock();

            try {
                Integer depthObj = DEPTH.get();
                int depth = depthObj != null ? depthObj : 0;
                if (depth == 0) {
                    boolean prev = fIsInternationalBuildBoolean.getBoolean(null);
                    PREV_VALUE.set(prev);
                    if (!prev) {
                        fIsInternationalBuildBoolean.setBoolean(null, true);
                    }
                }
                DEPTH.set(depth + 1);

                try {
                    return chain.proceed();
                } finally {
                    Integer dObj = DEPTH.get();
                    int d = (dObj != null ? dObj : 0) - 1;
                    if (d == 0) {
                        Boolean prev = PREV_VALUE.get();
                        PREV_VALUE.remove();
                        DEPTH.remove();
                        if (prev != null) {
                            fIsInternationalBuildBoolean.setBoolean(null, prev);
                        }
                    } else {
                        DEPTH.set(d);
                    }
                }
            } finally {
                INTL_LOCK.unlock();
            }

        }
    }
}
