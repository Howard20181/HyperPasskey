package io.github.howard20181.hyperpasskey;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import android.credentials.CredentialManager;
import android.os.Build;
import android.credentials.selection.IntentCreationResult;
import android.os.CancellationSignal;
import android.service.credentials.CallingAppInfo;
import android.util.Log;
import android.view.View;
import android.widget.CompoundButton;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import org.luckypray.dexkit.DexKitCacheBridge;
import org.luckypray.dexkit.exceptions.NoResultException;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.ClassData;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import io.github.libxposed.api.XposedModule;

@SuppressLint({"PrivateApi", "BlockedPrivateApi", "SoonBlockedPrivateApi"})
public class PasskeyHook extends XposedModule {
    private static final String TAG = "HyperPasskey";
    private static final String settingsPackageName = "com.android.settings";
    private static final String securityCenterPackageName = "com.miui.securitycenter";
    private static final String xiaomiScannerPackageName = "com.xiaomi.scanner";
    // GMS 凭据服务桥接目标：让 credman 的混合请求走 GMS RemoteService
    private static final String GMS_HYBRID_SERVICE =
            "com.google.android.gms/.auth.api.credentials.credman.service.RemoteService";
    // GMS 凭据选择器 Activity（Android 17 已重命名：旧 CredentialChooserActivity 不存在）
    private static final String GMS_CHOOSER_COMPONENT =
            "com.google.android.gms/.identitycredentials.ui.SignInCredentialChooserActivity";
    // Android 17 的 RequestSession 拆出的具体子类（基类是 abstract，实例化必经子类构造器）。
    // 注意：mHybridService 实际只在基类 RequestSession 声明一次（PROTECTED FINAL, String），
    // 并不存在字段遮蔽；必须 hook 到“真正会被实例化”的子类构造器才能覆盖字段。
    private static final String[] REQUEST_SESSION_SUBCLASSES = {
            "com.android.server.credentials.CreateRequestSession",
            "com.android.server.credentials.GetRequestSession",
            "com.android.server.credentials.GetCandidateRequestSession",
            "com.android.server.credentials.ClearRequestSession",
            "com.android.server.credentials.PrepareGetRequestSession"
    };
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

    /**
     * logd 在部分 HyperOS 版本上坏死（logcat 全丢），模块日志无法通过 logcat 观察。
     * 直接用文件日志输出（system_server 域下多候选路径，SELinux 会拒掉部分目录）。
     */
    private static final String[] FILE_LOG_PATHS = {
            "/data/system/hyperpasskey.log",
            "/cache/hyperpasskey.log",
            "/data/local/tmp/hyperpasskey.log",
            "/data/user_de/0/com.android.shell/hyperpasskey.log"
    };
    private static final SimpleDateFormat FILE_LOG_FMT = new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);
    private static String fileLogPath;

    private static void fileLog(String msg) {
        fileLog(msg, null);
    }

    private static void fileLog(String msg, Throwable tr) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(FILE_LOG_FMT.format(new Date())).append(" ").append(msg);
            if (tr != null) {
                sb.append(" :: ");
                StringWriter sw = new StringWriter();
                tr.printStackTrace(new PrintWriter(sw));
                sb.append(sw);
            }
            sb.append('\n');
            byte[] data = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // 已找到可用路径则直接追加
            if (fileLogPath != null) {
                appendFileLog(fileLogPath, data);
                return;
            }
            // 否则探测候选路径
            for (String p : FILE_LOG_PATHS) {
                try {
                    File f = new File(p);
                    if (!f.exists()) {
                        // 先创建空文件探测写权限
                        try (var fos = new FileOutputStream(f, false)) {
                            fos.write(new byte[0]);
                        }
                    }
                    appendFileLog(p, data);
                    fileLogPath = p;
                    return;
                } catch (Throwable ignored) {
                    // 此路径不可写，试下一个
                }
            }
        } catch (Throwable ignored) {
            // 文件日志失败不能影响 hook 逻辑
        }
    }

    private static void appendFileLog(String path, byte[] data) {
        try {
            try (var fos = new FileOutputStream(new File(path), true)) {
                fos.write(data);
            }
        } catch (Throwable ignored) {
            // 该路径写入失败（SELinux 等），由调用方尝试下一候选路径
        }
    }

    @Override
    public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        UnsafeUtils.INSTANCE.setXposedModule(this);
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
        fileLog("== hookSystemServer start, SDK_INT=" + Build.VERSION.SDK_INT + " ==");
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                try {
                    hookIntentFactory(classLoader);
                    fileLog("hookIntentFactory OK");
                } catch (NoSuchMethodException e) {
                    // Android 17 把 IntentFactory.getOemOverrideComponentName 删了，OEM UI 逻辑搬到 CredentialManagerUi
                    fileLog("hookIntentFactory NoSuchMethodException -> CredentialManagerUi fallback");
                    log(Log.WARN, TAG, "IntentFactory.getOemOverrideComponentName not found, falling back to CredentialManagerUi", e);
                    try {
                        hookCredentialManagerUi(classLoader);
                        fileLog("hookCredentialManagerUi OK");
                    } catch (Exception e2) {
                        fileLog("hookCredentialManagerUi FAILED: " + e2);
                        log(Log.ERROR, TAG, "hook CredentialManagerUi failed", e2);
                    }
                } catch (Exception e) {
                    fileLog("hookIntentFactory FAILED: " + e);
                    log(Log.ERROR, TAG, "hook IntentFactory failed", e);
                }
            }
            try {
                hookRequestSession(classLoader);
            } catch (Exception e) {
                fileLog("hookRequestSession FAILED: " + e);
                log(Log.ERROR, TAG, "hook RequestSession failed", e);
            }
            hookCredentialProviderDiscovery(classLoader);
            hookUiLaunchPath(classLoader);
            hookCredentialCapabilityProbe(classLoader);
            hookProviderBindProbe(classLoader);
            fileLog("hookSystemServer probes done");
        } catch (Throwable tr) {
            fileLog("hookSystemServer FAILED: " + tr);
            log(Log.ERROR, TAG, "Error hooking system service", tr);
        }
    }

    @Override
    public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!param.isFirstPackage()) return;
        var classLoader = param.getClassLoader();
        var packageName = param.getPackageName();
        Context ctx = ActivityThread.currentActivityThread().getSystemContext();
        var pm = ctx.getPackageManager();
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
        try (var bridge = DexKitCacheBridge.create(appTag, classLoader)) {
            hookPackage(packageName, classLoader, bridge);
            this.bridge = bridge;
        }
    }

    private void hookPackage(String packageName, ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        switch (packageName) {
            case "com.google.android.gms" -> {
                try {
                    hookGmsProcess(classLoader, bridge);
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "hook GMS process failed", t);
                    fileLogGms("hookGmsProcess outer FAILED: " + t);
                }
            }
            case settingsPackageName -> {
                Field fIsInternationalBuildBoolean = null;
                try {
                    var buildClass = classLoader.loadClass("miui.os.Build");
                    fIsInternationalBuildBoolean = buildClass.getDeclaredField("IS_INTERNATIONAL_BUILD");
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "find IS_INTERNATIONAL_BUILD failed", e);
                }
                var isInternationalBuildHooker = new IsInternationalBuildHooker(fIsInternationalBuildBoolean);
                try {
                    hookDefaultCombinedPicker(classLoader, isInternationalBuildHooker);
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "hook DefaultCombinedPicker failed", e);
                }
                try {
                    hookDefaultCombinedPreferenceController(classLoader, isInternationalBuildHooker);
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "hook DefaultCombinedPreferenceController failed", e);
                }
                try {
                    hookOnCombiPreferenceClickListener(classLoader, bridge, isInternationalBuildHooker);
                } catch (Exception e) {
                    log(Log.ERROR, TAG, "hook OnCombiPreferenceClickListener failed", e);
                }
                if (Build.VERSION.SDK_INT >= /*CINNAMON_BUN*/37) {
                    try {
                        hookCredentialManagerPreferenceController(classLoader, bridge);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook CredentialManagerPreferenceController failed", e);
                    }
                }
                if (Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    try {
                        hookDefaultAppPreferenceController(classLoader, isInternationalBuildHooker);
                    } catch (Exception e) {
                        log(Log.ERROR, TAG, "hook DefaultAppPreferenceController failed", e);
                    }
                }
            }
            case securityCenterPackageName -> {
                try {
                    securityCenterHook(classLoader, bridge);
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
        if (this.bridge != null) {
            this.bridge.destroy();
            this.bridge = null;
        }
        return true;
    }

    @Override
    public void onHotReloaded(@NonNull HotReloadedParam param) {
        UnsafeUtils.INSTANCE.setXposedModule(this);
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
                    System.loadLibrary("dexkit");
                    DexKitCacheBridge.init(MemoryCache.INSTANCE);
                    var appTag = packageName + ":" + versionName + "-" + versionCode;
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
            } catch (NoSuchMethodException e) {
                log(Log.ERROR, TAG, "hook MiFiDoBean failed", e);
            }
        }
    }

    @RequiresApi(/*CINNAMON_BUN*/37)
    private void hookCredentialManagerPreferenceController(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) throws ClassNotFoundException, NoSuchMethodException, NoSuchFieldException {
        var combiPreferenceClass = classLoader.loadClass("com.android.settings.applications.credentials.CredentialManagerPreferenceController$CombiPreference");
        var onBindViewHolder = combiPreferenceClass.getDeclaredMethod("onBindViewHolder", classLoader.loadClass("androidx.preference.PreferenceViewHolder"));
        var mChecked = combiPreferenceClass.getDeclaredField("mChecked");
        mChecked.setAccessible(true);
        var mOnClickListener = combiPreferenceClass.getDeclaredField("mOnClickListener");
        mOnClickListener.setAccessible(true);
        var mSwitch = combiPreferenceClass.getDeclaredField("mSwitch");
        mSwitch.setAccessible(true);
        var maybeUpdateContentDescriptionMethod = combiPreferenceClass.getDeclaredMethod("maybeUpdateContentDescription");
        var viewHolder = classLoader.loadClass("androidx.recyclerview.widget.RecyclerView$ViewHolder");
        var itemViewField = viewHolder.getDeclaredField("itemView");
        itemViewField.setAccessible(true);
        var R$idClass = classLoader.loadClass("com.android.settingslib.R$id");
        var switchWidget = R$idClass.getDeclaredField("switchWidget");
        switchWidget.setAccessible(true);
        var onCheckChangedMatcher = MethodMatcher.create()
                .name("onCheckChanged")
                .paramTypes(combiPreferenceClass, boolean.class)
                .anyOf(
                        MethodMatcher.create()
                                .addInvoke("Lcom/android/settings/applications/credentials/CredentialManagerPreferenceController;->togglePackageNameEnabled(Ljava/lang/String;)Z"),
                        MethodMatcher.create()
                                .addInvoke("Lcom/android/settings/applications/credentials/CredentialManagerPreferenceController;->togglePackageNameDisabled(Ljava/lang/String;)V"));
        bridge.getMethods(FindMethod.create()
                .searchPackages("com.android.settings.applications.credentials")
                .matcher(onCheckChangedMatcher)
        ).forEach(methodData -> {
            try {
                var onCheckChangedMethod = methodData.getMethodInstance(classLoader);
                hookE(onBindViewHolder).intercept(chain -> {
                    var result = chain.proceed();
                    var combiPreference = chain.getThisObject();
                    if (mSwitch.get(combiPreference) == null && itemViewField.get(chain.getArg(0)) instanceof View itemView) {
                        var checkableView = itemView.findViewById(switchWidget.getInt(null));
                        if (checkableView instanceof CompoundButton switchView) {
                            switchView.setChecked(mChecked.getBoolean(combiPreference));
                            switchView.setOnClickListener(buttonView -> {
                                try {
                                    var clickListener = mOnClickListener.get(combiPreference);
                                    if (clickListener == null) {
                                        return;
                                    }
                                    var isChecked = switchView.isChecked();
                                    boolean accepted = (boolean) getInvoker(onCheckChangedMethod)
                                            .invoke(clickListener, combiPreference, isChecked);
                                    if (!accepted) {
                                        UnsafeUtils.INSTANCE.setBooleanField(mChecked, combiPreference, false);
                                        switchView.setChecked(false);
                                    }
                                } catch (IllegalAccessException | InvocationTargetException e) {
                                    log(Log.ERROR, TAG, "Failed setOnCheckedChangeListener", e);
                                }
                            });
                            UnsafeUtils.INSTANCE.setObjectField(mSwitch, combiPreference, switchView);
                            getInvoker(maybeUpdateContentDescriptionMethod).invoke(combiPreference);
                        }
                    }
                    return result;
                });
            } catch (NoSuchMethodException e) {
                log(Log.ERROR, TAG, "Failed to find onCheckChanged", e);
            }
        });
    }

    private void hookDefaultCombinedPreferenceController(ClassLoader classLoader, Hooker isInternationalBuildHooker) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPreferenceController");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("getCombinedProviderInfos", CredentialManager.class, int.class);
                deoptimize(aMethod);
                hookE(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookDefaultAppPreferenceController(ClassLoader classLoader, Hooker isInternationalBuildHooker) throws ClassNotFoundException, NoSuchMethodException {
        var iClass = classLoader.loadClass("com.android.settings.applications.defaultapps.DefaultAppPreferenceController");
        var preferenceClass = classLoader.loadClass("androidx.preference.Preference");
        var aMethod = iClass.getDeclaredMethod("updateState", preferenceClass);
        deoptimize(aMethod);
        hookE(aMethod).intercept(isInternationalBuildHooker);
    }

    private void hookDefaultCombinedPicker(ClassLoader classLoader, Hooker isInternationalBuildHooker) throws ClassNotFoundException {
        var iClass = classLoader.loadClass("com.android.settings.applications.credentials.DefaultCombinedPicker");
        if (iClass != null) {
            try {
                var aMethod = iClass.getDeclaredMethod("setDefaultKey", String.class);
                deoptimize(aMethod);
                hookE(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException ignored) {
            }
        }
    }

    private void hookOnCombiPreferenceClickListener(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge, Hooker isInternationalBuildHooker) {
        var onLeftSideClickedMatcher = MethodMatcher.create()
                .name("onLeftSideClicked")
                .paramCount(0)
                .anyOf(
                        MethodMatcher.create()
                                .addInvoke("Lcom/android/settings/applications/credentials/CombinedProviderInfo;->launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)Z"),
                        MethodMatcher.create()
                                .addInvoke("Lcom/android/settings/applications/credentials/CombinedProviderInfo;->launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;Ljava/lang/CharSequence;I)V"));
        bridge.getMethods(FindMethod.create()
                .searchPackages("com.android.settings.applications.credentials")
                .matcher(onLeftSideClickedMatcher)
        ).forEach(methodData -> {
            try {
                var aMethod = methodData.getMethodInstance(classLoader);
                deoptimize(aMethod);
                hookE(aMethod).intercept(isInternationalBuildHooker);
            } catch (NoSuchMethodException e) {
                log(Log.ERROR, TAG, "hook onLeftSideClicked failed", e);
            }
        });
    }

    private void deoptimizeMethods(Class<?> clazz, String... names) {
        var list = Arrays.asList(names);
        Arrays.stream(clazz.getDeclaredMethods())
                .filter(method -> list.contains(method.getName()))
                .forEach(this::deoptimize);
    }

    private void hookRequestSession(ClassLoader classLoader) throws NoSuchMethodException, ClassNotFoundException, NoSuchFieldException {
        var cRequestSession = classLoader.loadClass("com.android.server.credentials.RequestSession");
        try {
            deoptimizeMethods(classLoader.loadClass("com.android.server.credentials.ProviderGetSession"), "createNewSession");
            deoptimizeMethods(classLoader.loadClass("com.android.server.credentials.ProviderCreateSession"), "createNewSession");
        } catch (ClassNotFoundException e) {
            log(Log.WARN, TAG, "ProviderGetSession or ProviderCreateSession not found, skipping deoptimize", e);
        }

        // 实测 Android 17 (HyperOS)：mHybridService 只在基类 RequestSession 声明一次
        // (PROTECTED FINAL String)，不存在字段遮蔽。基类是 ABSTRACT，实例化必经具体子类构造器，
        // 而子类构造器签名跨版本差异极大（Android 15/16/17 各不同），不能硬编码签名。
        // 修复策略：拿到基类字段引用后，把“基类 + 所有已知具体子类”的构造器全部 hook，
        // 无论哪个构造器被调用，构造完成后统一用 Unsafe 覆盖 mHybridService 指向 GMS。
        Field fHybridService = cRequestSession.getDeclaredField("mHybridService");
        int hookedCtors = 0;

        // 1) 基类构造器（abstract 类构造器只能被子类 super() 触发，hook 后同样能拦截到）
        try {
            for (var ctor : cRequestSession.getDeclaredConstructors()) {
                hookedCtors += hookOneRequestSessionCtor(ctor, fHybridService);
            }
        } catch (Throwable t) {
            fileLog("hook base RequestSession ctor failed: " + t);
        }

        // 2) 所有已知具体子类的全部构造器
        for (String name : REQUEST_SESSION_SUBCLASSES) {
            try {
                var subClass = classLoader.loadClass(name);
                for (var ctor : subClass.getDeclaredConstructors()) {
                    hookedCtors += hookOneRequestSessionCtor(ctor, fHybridService);
                }
                log(Log.INFO, TAG, "Hooked RequestSession subclass: " + name);
            } catch (ClassNotFoundException ignored) {
                // 旧版 Android 没有这个子类，正常
            } catch (Throwable t) {
                fileLog("hook RequestSession subclass " + name + " failed: " + t);
                log(Log.ERROR, TAG, "Failed to hook RequestSession subclass: " + name, t);
            }
        }

        fileLog("hookRequestSession done, hooked ctors = " + hookedCtors
                + " (mHybridService declaring: " + fHybridService.getDeclaringClass().getName() + ")");
    }

    /** Hook 单个 RequestSession 构造器：proceed 完成后用 Unsafe 覆盖 mHybridService。返回 1 表示成功。 */
    private int hookOneRequestSessionCtor(Constructor<?> ctor, Field fHybridService) {
        try {
            hookE(ctor).intercept(chain -> {
                chain.proceed();
                try {
                    // 探针：打印构造参数里所有 Set/String，确认 mEnabledProviders 候选集合内容
                    try {
                        var args = chain.getArgs();
                        StringBuilder sb = new StringBuilder("ctor[" + chain.getThisObject().getClass().getSimpleName() + "] args:");
                        for (int i = 0; i < args.size(); i++) {
                            Object a = args.get(i);
                            sb.append(" <").append(i).append(">=");
                            if (a instanceof Set) {
                                sb.append("Set{");
                                for (Object e : (Set<?>) a) sb.append(e).append(';');
                                sb.append('}');
                            } else if (a instanceof String) {
                                sb.append("'").append(a).append("'");
                            } else if (a != null) {
                                String s = a.toString();
                                sb.append(s.length() > 300 ? s.substring(0, 300) + "..." : s);
                            } else {
                                sb.append("null");
                            }
                        }
                        fileLog(sb.toString());
                    } catch (Throwable ignored) {
                    }
                    UnsafeUtils.INSTANCE.setObjectField(fHybridService, chain.getThisObject(), GMS_HYBRID_SERVICE);
                    fileLog("mHybridService <- GMS on " + chain.getThisObject().getClass().getName());
                } catch (Throwable t) {
                    fileLog("setObjectField(mHybridService) failed", t);
                }
                return null;
            });
            return 1;
        } catch (Throwable t) {
            fileLog("hookE ctor failed: " + ctor + " :: " + t);
            return 0;
        }
    }

    /** 探针：hook CredentialManagerService 的候选 provider 决策，记录系统实际纳入了哪些 provider。 */
    private void hookCredentialProviderDiscovery(ClassLoader classLoader) {
        try {
            var cls = classLoader.loadClass("com.android.server.credentials.CredentialManagerService");
            for (String mn : new String[]{"getCredentialProviderServicesLocked",
                    "getOrConstructSystemServiceListLock", "constructSystemServiceListLocked"}) {
                for (var m : cls.getDeclaredMethods()) {
                    if (m.getName().equals(mn) && m.getParameterCount() == 1 && m.getParameterTypes()[0] == int.class) {
                        hookE(m).intercept(chain -> {
                            Object r;
                            try {
                                r = chain.proceed();
                            } catch (Throwable t) {
                                fileLog("probe " + m.getName() + " threw: " + t);
                                throw t;
                            }
                            try {
                                fileLog("probe " + m.getName() + " -> " + r);
                            } catch (Throwable ignored) {
                            }
                            return r;
                        });
                        fileLog("probe hooked: CredentialManagerService." + mn);
                    }
                }
            }
        } catch (Throwable t) {
            fileLog("hookCredentialProviderDiscovery failed: " + t);
        }
    }

    /** 探针：hook UI 启动路径，确认流程是否到达弹窗环节。 */
    private void hookUiLaunchPath(ClassLoader classLoader) {
        try {
            var cls = classLoader.loadClass("com.android.server.credentials.CredentialManagerUi");
            for (String mn : new String[]{"createPendingIntent", "createIntentForAutofill", "launchPendingIntent", "showUi"}) {
                for (var m : cls.getDeclaredMethods()) {
                    if (m.getName().equals(mn)) {
                        hookE(m).intercept(chain -> {
                            Object r;
                            try {
                                fileLog("UI probe ENTER " + cls.getSimpleName() + "." + m.getName() + " args=" + chain.getArgs());
                                r = chain.proceed();
                                fileLog("UI probe EXIT  " + cls.getSimpleName() + "." + m.getName() + " -> " + r);
                                return r;
                            } catch (Throwable t) {
                                fileLog("UI probe THREW " + cls.getSimpleName() + "." + m.getName() + " :: " + t);
                                throw t;
                            }
                        });
                        fileLog("UI probe hooked: CredentialManagerUi." + mn);
                    }
                }
            }
        } catch (Throwable t) {
            fileLog("hookUiLaunchPath failed: " + t);
        }
    }

    /** 探针：hook CredentialProviderInfo.hasCapability / isSystemProvider，确认 GMS 的类型匹配结果。 */
    private void hookCredentialCapabilityProbe(ClassLoader classLoader) {
        try {
            var cls = classLoader.loadClass("android.credentials.CredentialProviderInfo");
            for (var m : cls.getDeclaredMethods()) {
                if (m.getName().equals("hasCapability") && m.getParameterCount() == 1) {
                    hookE(m).intercept(chain -> {
                        boolean r;
                        try {
                            r = (Boolean) chain.proceed();
                        } catch (Throwable t) {
                            fileLog("capability probe THREW: " + t);
                            throw t;
                        }
                        try {
                            String cn = "?";
                            try {
                                var thisObj = chain.getThisObject();
                                if (thisObj != null) {
                                    var gci = thisObj.getClass().getMethod("getComponentName");
                                    cn = String.valueOf(gci.invoke(thisObj));
                                }
                            } catch (Throwable ignored) {
                            }
                            fileLog("hasCapability(" + chain.getArgs().get(0) + ") on " + cn + " -> " + r);
                        } catch (Throwable ignored) {
                        }
                        return r;
                    });
                    fileLog("capability probe hooked: CredentialProviderInfo." + m.getName());
                }
            }
            // isServiceCapableLocked 是 impl 的私有方法，直接 hook CredentialManagerServiceImpl 判断入口
            var implCls = classLoader.loadClass("com.android.server.credentials.CredentialManagerServiceImpl");
            for (var m : implCls.getDeclaredMethods()) {
                if (m.getName().equals("initiateProviderSessionForRequestLocked") && m.getParameterCount() == 2) {
                    hookE(m).intercept(chain -> {
                        Object r;
                        try {
                            r = chain.proceed();
                        } catch (Throwable t) {
                            fileLog("initiateProviderSession probe THREW: " + t);
                            throw t;
                        }
                        try {
                            String mInfo = "?";
                            try {
                                var f = implCls.getDeclaredField("mInfo");
                                f.setAccessible(true);
                                mInfo = String.valueOf(f.get(chain.getThisObject()));
                            } catch (Throwable ignored) {
                            }
                            fileLog("initiateProviderSessionForRequestLocked types=" + chain.getArgs().get(1) + " mInfo=" + mInfo + " -> " + r);
                        } catch (Throwable ignored) {
                        }
                        return r;
                    });
                    fileLog("impl probe hooked: initiateProviderSessionForRequestLocked");
                }
            }
        } catch (Throwable t) {
            fileLog("hookCredentialCapabilityProbe failed: " + t);
        }
    }

    /**
     * 决定性探针：追踪 ProviderSession 的 bind/响应生命周期，区分“GMS 没被 bind /
     * bind 了但没响应 / 响应了但空条目 / UI 启动被跳过”四种卡点。
     * 方法签名来自对 Android 17 (HyperOS 4) services.jar 的 baksmali 反汇编。
     */
    private void hookProviderBindProbe(ClassLoader classLoader) {
        Class<?> cProviderCreate = tryLoad(classLoader, "com.android.server.credentials.ProviderCreateSession");
        Class<?> cProviderGet = tryLoad(classLoader, "com.android.server.credentials.ProviderGetSession");
        Class<?> cCreateReq = tryLoad(classLoader, "com.android.server.credentials.CreateRequestSession");
        Class<?> cGetReq = tryLoad(classLoader, "com.android.server.credentials.GetRequestSession");
        Class<?> cReqSession = tryLoad(classLoader, "com.android.server.credentials.RequestSession");
        Class<?> cUi = tryLoad(classLoader, "com.android.server.credentials.CredentialManagerUi");
        Class<?> cRemoteSvc = tryLoad(classLoader, "com.android.server.credentials.RemoteCredentialService");
        Class<?> cBeginCreate = tryLoad(classLoader, "android.service.credentials.BeginCreateCredentialResponse");
        Class<?> cBeginGet = tryLoad(classLoader, "android.service.credentials.BeginGetCredentialResponse");
        Class<?> cStatus = tryLoad(classLoader, "com.android.server.credentials.ProviderSession$Status");
        Class<?> cSource = tryLoad(classLoader, "com.android.server.credentials.ProviderSession$CredentialsSource");

        // provider bind 请求发起（RemoteCredentialService 收到 onBeginXxx 即 bind 已排队/完成）
        if (cRemoteSvc != null) {
            hookSimpleEnter(cRemoteSvc, "onBeginCreateCredential",
                    new Class<?>[]{tryLoad(classLoader, "android.service.credentials.BeginCreateCredentialRequest")},
                    "RCS.onBeginCreateCredential");
            hookSimpleEnter(cRemoteSvc, "onBeginGetCredential",
                    new Class<?>[]{tryLoad(classLoader, "android.service.credentials.BeginGetCredentialRequest")},
                    "RCS.onBeginGetCredential");
        }

        // ProviderSession 响应结局：成功(带条目)/失败(带错误码)/服务死亡
        if (cProviderCreate != null) {
            hookResponseSuccess(cProviderCreate, cBeginCreate, "PCS");
            hookResponseFailure(cProviderCreate, "PCS");
            hookServiceDied(cProviderCreate, cRemoteSvc, "PCS");
        }
        if (cProviderGet != null) {
            hookResponseSuccess(cProviderGet, cBeginGet, "PGS");
            hookResponseFailure(cProviderGet, "PGS");
            hookServiceDied(cProviderGet, cRemoteSvc, "PGS");
        }

        // RequestSession 状态机推进 + UI 启动 + app 最终结果
        if (cCreateReq != null) {
            hookStatusChanged(cCreateReq, cStatus, cSource, "CreateReqSession");
            hookLaunchUi(cCreateReq, "CreateReqSession");
        }
        if (cGetReq != null) {
            hookStatusChanged(cGetReq, cStatus, cSource, "GetReqSession");
            hookLaunchUi(cGetReq, "GetReqSession");
        }
        if (cReqSession != null) {
            hookSimpleHook(cReqSession, "respondToClientWithErrorAndFinish", new Class<?>[]{String.class, String.class}, "ReqSession.appError", true);
            hookSimpleHook(cReqSession, "respondToClientWithResponseAndFinish", new Class<?>[]{Object.class}, "ReqSession.appResponse", true);
        }

        // CredentialManagerUi 实例化 = 弹 UI 前置
        if (cUi != null) {
            for (var ctor : cUi.getDeclaredConstructors()) {
                if (ctor.getParameterCount() == 4) {
                    hookE(ctor).intercept(chain -> {
                        try {
                            fileLog(">>> CredentialManagerUi CONSTRUCTED (pre-UI) this=" + chain.getThisObject());
                        } catch (Throwable ignored) {
                        }
                        return chain.proceed();
                    });
                    fileLog("UI probe hooked: CredentialManagerUi.<init>");
                }
            }
        }
        fileLog("hookProviderBindProbe done");
    }

    private Class<?> tryLoad(ClassLoader cl, String name) {
        try {
            return cl.loadClass(name);
        } catch (Throwable t) {
            fileLog("tryLoad failed: " + name + " :: " + t);
            return null;
        }
    }

    /** hook 无返回值方法，进入时打日志 */
    private void hookSimpleEnter(Class<?> cls, String name, Class<?>[] params, String tag) {
        if (params.length > 0 && params[0] == null) return;
        try {
            var m = cls.getDeclaredMethod(name, params);
            hookE(m).intercept(chain -> {
                try {
                    fileLog(tag + " ENTER this=" + cls.getSimpleName() + "@" + System.identityHashCode(chain.getThisObject())
                            + " args=" + chain.getArgs());
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("bind probe hooked: " + cls.getSimpleName() + "." + name);
        } catch (Throwable t) {
            fileLog("bind probe FAILED hook " + cls.getSimpleName() + "." + name + " :: " + t);
        }
    }

    /** hook 有返回值方法，进入与返回都打日志 */
    private void hookSimpleHook(Class<?> cls, String name, Class<?>[] params, String tag, boolean enter) {
        try {
            var m = cls.getDeclaredMethod(name, params);
            hookE(m).intercept(chain -> {
                if (enter) {
                    try {
                        fileLog(tag + " ENTER this=" + cls.getSimpleName() + " args=" + chain.getArgs());
                    } catch (Throwable ignored) {
                    }
                }
                Object r = chain.proceed();
                try {
                    fileLog(tag + " EXIT -> " + r);
                } catch (Throwable ignored) {
                }
                return r;
            });
            fileLog("lifecycle probe hooked: " + cls.getSimpleName() + "." + name);
        } catch (Throwable t) {
            fileLog("lifecycle probe FAILED hook " + cls.getSimpleName() + "." + name + " :: " + t);
        }
    }

    /** ProviderSession.onProviderResponseSuccess(响应) —— 成功响应内容 */
    private void hookResponseSuccess(Class<?> cls, Class<?> responseType, String tag) {
        if (responseType == null) return;
        try {
            var m = cls.getDeclaredMethod("onProviderResponseSuccess", responseType);
            hookE(m).intercept(chain -> {
                try {
                    Object resp = chain.getArg(0);
                    fileLog(tag + ".onProviderResponseSuccess this=" + cls.getSimpleName()
                            + "@" + System.identityHashCode(chain.getThisObject())
                            + " resp=" + summarizeResponse(resp));
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("resp probe hooked: " + cls.getSimpleName() + ".onProviderResponseSuccess");
        } catch (Throwable t) {
            fileLog("resp probe FAILED hook " + cls.getSimpleName() + ".onProviderResponseSuccess :: " + t);
        }
    }

    /** ProviderSession.onProviderResponseFailure(int, Exception) —— 失败错误码与异常 */
    private void hookResponseFailure(Class<?> cls, String tag) {
        try {
            var m = cls.getDeclaredMethod("onProviderResponseFailure", int.class, Exception.class);
            hookE(m).intercept(chain -> {
                try {
                    Object ex = chain.getArg(1);
                    String exStr = ex == null ? "null" : ex.getClass().getName() + ": " + ex.toString();
                    if (exStr.length() > 300) exStr = exStr.substring(0, 300);
                    fileLog(tag + ".onProviderResponseFailure code=" + chain.getArg(0)
                            + " ex=" + exStr);
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("resp probe hooked: " + cls.getSimpleName() + ".onProviderResponseFailure");
        } catch (Throwable t) {
            fileLog("resp probe FAILED hook " + cls.getSimpleName() + ".onProviderResponseFailure :: " + t);
        }
    }

    /** ProviderSession.onProviderServiceDied —— GMS 服务死亡/断连 */
    private void hookServiceDied(Class<?> cls, Class<?> remoteSvcType, String tag) {
        if (remoteSvcType == null) return;
        try {
            var m = cls.getDeclaredMethod("onProviderServiceDied", remoteSvcType);
            hookE(m).intercept(chain -> {
                try {
                    fileLog(tag + ".onProviderServiceDied this=" + cls.getSimpleName()
                            + " svc=" + chain.getArg(0));
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("resp probe hooked: " + cls.getSimpleName() + ".onProviderServiceDied");
        } catch (Throwable t) {
            fileLog("resp probe FAILED hook " + cls.getSimpleName() + ".onProviderServiceDied :: " + t);
        }
    }

    /** RequestSession.onProviderStatusChanged —— 状态机全貌 */
    private void hookStatusChanged(Class<?> cls, Class<?> statusType, Class<?> sourceType, String tag) {
        try {
            var m = cls.getDeclaredMethod("onProviderStatusChanged", statusType, ComponentName.class, sourceType);
            hookE(m).intercept(chain -> {
                try {
                    fileLog(tag + ".onProviderStatusChanged status=" + chain.getArg(0)
                            + " comp=" + chain.getArg(1) + " source=" + chain.getArg(2));
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("status probe hooked: " + cls.getSimpleName() + ".onProviderStatusChanged");
        } catch (Throwable t) {
            fileLog("status probe FAILED hook " + cls.getSimpleName() + ".onProviderStatusChanged :: " + t);
        }
    }

    /** RequestSession.launchUiWithProviderData(ArrayList) —— UI 真正启动点 */
    private void hookLaunchUi(Class<?> cls, String tag) {
        try {
            var m = cls.getDeclaredMethod("launchUiWithProviderData", ArrayList.class);
            hookE(m).intercept(chain -> {
                try {
                    fileLog(">>> " + tag + ".launchUiWithProviderData CALLED data=" + chain.getArg(0));
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            fileLog("ui-launch probe hooked: " + cls.getSimpleName() + ".launchUiWithProviderData");
        } catch (Throwable t) {
            fileLog("ui-launch probe FAILED hook " + cls.getSimpleName() + ".launchUiWithProviderData :: " + t);
        }
    }

    /** 提取响应对象里能拿到的条目摘要（反射，避免版本差异） */
    private static String summarizeResponse(Object resp) {
        if (resp == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append(resp.getClass().getSimpleName());
        for (String mn : new String[]{"getCreateEntries", "getCredentialEntries", "getRemoteCreateEntry", "getRemoteEntry"}) {
            try {
                var m = resp.getClass().getMethod(mn);
                Object v = m.invoke(resp);
                if (v instanceof java.util.List) {
                    sb.append(" ").append(mn).append("=[").append(((java.util.List<?>) v).size()).append(" items]");
                } else if (v != null) {
                    sb.append(" ").append(mn).append("=").append(v);
                }
            } catch (Throwable ignored) {
            }
        }
        String s = sb.toString();
        return s.length() > 400 ? s.substring(0, 400) : s;
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
        fileLog("hookIntentFactory: got method, hooking now");
        hookE(mGetOemOverrideComponentName).intercept(chain -> {
            var args = chain.getArgs();
            fileLog("IntentFactory.getOemOverrideComponentName CALLED, args=" + args.size());
            if (args.size() >= 2 && args.get(0) instanceof Context context && args.get(1) instanceof IntentCreationResult.Builder intentResultBuilder) {
                final String oemComponentString = GMS_CHOOSER_COMPONENT;
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
                                fileLog("OEM override -> " + oemComponentString + " (enabled, exported)");
                                return oemComponentName;
                            } else {
                                fileLog("OEM component exists but NOT usable: enabled=" + oemComponentEnabled
                                        + " exported=" + info.exported + ", falling through to default");
                            }
                        } catch (PackageManager.NameNotFoundException e) {
                            fileLog("GMS chooser component NOT FOUND on device: " + oemComponentString);
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

    /**
     * Android 17 fallback：IntentFactory.getOemOverrideComponentName 被删除，
     * OEM UI 逻辑搬进 com.android.server.credentials.CredentialManagerUi。
     * Hook 其 createPendingIntent / createIntentForAutofill，在返回前把 Intent/PendingIntent 的
     * component 强制改为 GMS SignInCredentialChooserActivity。
     */
    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private void hookCredentialManagerUi(ClassLoader classLoader) {
        final ComponentName targetComponent = ComponentName.unflattenFromString(GMS_CHOOSER_COMPONENT);
        if (targetComponent == null) {
            log(Log.ERROR, TAG, "Unflatten GMS_CHOOSER_COMPONENT failed: " + GMS_CHOOSER_COMPONENT);
            return;
        }

        Class<?> cUi;
        try {
            cUi = classLoader.loadClass("com.android.server.credentials.CredentialManagerUi");
        } catch (ClassNotFoundException e) {
            log(Log.WARN, TAG, "CredentialManagerUi not found, Android 17 OEM UI hook skipped");
            return;
        }
        log(Log.INFO, TAG, "Hooking CredentialManagerUi (Android 17 OEM UI path)");

        for (var m : cUi.getDeclaredMethods()) {
            if (!m.getName().equals("createPendingIntent") && !m.getName().equals("createIntentForAutofill")) {
                continue;
            }
            try {
                hookE(m).intercept(chain -> {
                    var result = chain.proceed();
                    try {
                        if (result instanceof PendingIntent pi) {
                            Intent inner = extractIntentFromPendingIntent(pi);
                            if (inner != null) {
                                inner.setComponent(targetComponent);
                            }
                        } else if (result instanceof Intent intent) {
                            intent.setComponent(targetComponent);
                        }
                    } catch (Throwable t) {
                        log(Log.ERROR, TAG, "CredentialManagerUi." + m.getName() + " rewrite failed", t);
                    }
                    return result;
                });
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "Hook CredentialManagerUi." + m.getName() + " failed", t);
            }
        }
    }

    /**
     * 反射拿 PendingIntent 内部 Intent（不同 Android 版本 IntentSender 字段名差异较大，失败返回 null）。
     * Android 17 上：IntentSender -> mIntents (Intent[]) 或 mIntent (Intent)。
     */
    private static Intent extractIntentFromPendingIntent(PendingIntent pi) {
        IntentSender sender;
        try {
            sender = pi.getIntentSender();
        } catch (Throwable t) {
            return null;
        }
        for (String fName : new String[]{"mIntents", "mIntent", "intent", "mBaseIntent"}) {
            try {
                var f = sender.getClass().getDeclaredField(fName);
                f.setAccessible(true);
                Object obj = f.get(sender);
                if (obj instanceof Intent[] intents && intents.length > 0) {
                    return intents[0];
                }
                if (obj instanceof Intent intent) {
                    return intent;
                }
            } catch (NoSuchFieldException ignored) {
                // 试下一个字段名
            } catch (Throwable ignored) {
                // 不可访问
            }
        }
        return null;
    }


    /**
     * GMS 进程（非 root uid）无法写 /data/system/hyperpasskey.log，
     * 用 adb 预创建并 chmod 666 的独立日志文件。全部 IO 静默失败。
     */
    private static void fileLogGms(String msg) {
        Log.i(TAG, "[GMS] " + msg);
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(FILE_LOG_FMT.format(new Date())).append(" ").append(msg).append('\n');
            byte[] data = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            // GMS 进程 SELinux 域不可写 shell_data_file(/data/local/tmp)，写自己 files 目录
            appendFileLog("/data/data/com.google.android.gms/files/hyperpasskey_gms.log", data);
            appendFileLog("/data/user/0/com.google.android.gms/files/hyperpasskey_gms.log", data);
        } catch (Throwable ignored) {
        }
    }

    /**
     * GMS 进程内修复 GPM 特权浏览器白名单误杀第三方浏览器的问题。
     *
     * 背景：GMS CredentialProvider 创建 passkey 时，内部类（GMS 26.32.34 中混淆名为
     * <code>ndt</code>）的 <code>b(String privilegedAllowlistJson)</code> 会校验"调用方包名"是否
     * 在 Phenotype 服务器下发的 privileged allowlist
     * （flag: GisPasswordAndPasskeyProvider__privileged_allowlist_json）中。第三方浏览器
     * （如 Via）不在白名单 → 抛 IllegalStateException("Origin is not being returned as the
     * calling app did not match the privileged allowlist") → 前端收到
     * "[28442] Invalid calling package."。
     *
     * 修复：hook该方法，直接返回自身字段中保存的 origin 值，跳过白名单校验。
     */
    private void hookGmsProcess(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        fileLogGms("== hookGmsProcess start, SDK_INT=" + Build.VERSION.SDK_INT + " ==");
        hookNdtAllowlistReturn(classLoader, bridge);
        fileLogGms("== hookGmsProcess done ==");
    }

    /**
     * 允许 GPM privileged allowlist 错误拒绝：定位并 hook 校验类，
     * 使其 b(String privilegedAllowlistJson) 直接返回自身 origin 字段。
     *
     * 类名跨版本混淆，定位策略：
     * 1) DexKit：按异常文案常量 "privileged allowlist" 在 GMS dex 中定位持有该字符串、
     *    且含 (String)->String 方法的类；
     * 2) 找不到时回退已知混淆名（GMS 26.32.34 = ndt）。
     *
     * origin 字段跨版本/字符名不稳定，运行时从对象的 String 实例字段里取
     * 以 http 开头的值（该类的字段依次为 调用方包名 / origin(URL) / 签名集 / SigningInfo）。
     */
    private void hookNdtAllowlistReturn(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
        Class<?> targetCls = null;
        var allowlistMsg = "privileged allowlist";
        // bridge 由外层 hookLifecycle 持有并统一关闭，这里不重复 close
        var b = bridge;
        try {
            var clzList = new ArrayList<ClassData>();
            b.withBridge(raw -> clzList.addAll(raw.findClass(FindClass.create()
                    .matcher(ClassMatcher.create().usingStrings(allowlistMsg)))));
            for (var cd : clzList) {
                try {
                    var c = classLoader.loadClass(cd.getName());
                    for (var m : c.getDeclaredMethods()) {
                        // 校验方法是实例方法 (String) -> String（包名入参、返回 origin）
                        if (m.getParameterCount() == 1 && m.getParameterTypes()[0] == String.class
                                && m.getReturnType() == String.class
                                && !java.lang.reflect.Modifier.isStatic(m.getModifiers())) {
                            hookAllowlistMethod(m);
                            fileLogGms("allowlist bypass hooked via DexKit: " + cd.getName() + "." + m.getName());
                            return;
                        }
                    }
                } catch (Throwable t) {
                    fileLogGms("DexKit candidate " + cd.getName() + " FAILED: " + t);
                }
            }
        } catch (Throwable t) {
            fileLogGms("DexKit locate allowlist class FAILED: " + t);
        }
        // 回退：GMS 26.32.34
        try {
            var cls = classLoader.loadClass("ndt");
            var m = cls.getDeclaredMethod("b", String.class);
            hookAllowlistMethod(m);
            fileLogGms("allowlist bypass hooked via fallback class ndt.b");
        } catch (Throwable t) {
            fileLogGms("hookNdtAllowlistReturn all-FAILED: " + t);
        }
    }

    /** hook (String)->String 的 whitelist 校验方法：拦截后返回 this 的 origin 字段值。 */
    private void hookAllowlistMethod(java.lang.reflect.Method m) {
        var flds = m.getDeclaringClass().getDeclaredFields();
        for (var f : flds) {
            f.setAccessible(true);
        }
        hookE(m).intercept(chain -> {
            Object self = chain.getThisObject();
            String origin = null;
            try {
                for (var f : flds) {
                    if (f.getType() != String.class || java.lang.reflect.Modifier.isStatic(f.getModifiers()))
                        continue;
                    Object v = f.get(self);
                    if (v instanceof String s && s.startsWith("http")) {
                        origin = s;
                        break;
                    }
                }
            } catch (Throwable ignored) {
            }
            if (origin == null) origin = (String) chain.proceed();
            try {
                fileLogGms("allowlist check bypassed, origin=" + origin);
            } catch (Throwable ignored) {
            }
            return origin;
        });
    }

    private void securityCenterHook(ClassLoader classLoader, DexKitCacheBridge.RecyclableBridge bridge) {
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
                            .anyOf(
                                    MethodMatcher.create()
                                            .paramTypes(Context.class, String.class, int.class),
                                    MethodMatcher.create()
                                            .paramTypes(String.class, int.class))
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
                    ));
            hookE(mConfigForAutofillService.getMethodInstance(classLoader)).intercept(chain -> null);
        } catch (NoSuchMethodException e) {
            log(Log.WARN, TAG, "hook configForAutofillService", e);
        } catch (NoResultException e) {
            log(Log.WARN, TAG, "dexkit search err", e);
        }
        try {
            var mSetStringArrayResourceConfigIfNeed = bridge.getMethod(FindMethod.create()
                    .searchInClass(classDataList)
                    .matcher(MethodMatcher.create()
                            .anyOf(
                                    MethodMatcher.create()
                                            .paramTypes(Context.class, String.class, int.class),
                                    MethodMatcher.create()
                                            .paramTypes(String.class, int.class))
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
                    ));
            hookE(mSetDefaultConfigForAutofillAndCredentialManager.getMethodInstance(classLoader)).intercept(chain -> null);
        } catch (NoSuchMethodException e) {
            log(Log.ERROR, TAG, "hook setDefaultConfigForAutofillAndCredentialManager", e);
        } catch (NoResultException e) {
            log(Log.ERROR, TAG, "dexkit search err", e);
        }
    }

    private record IsInternationalBuildHooker(
            Field fIsInternationalBuildBoolean) implements Hooker {
        private static final ReentrantLock INTL_LOCK = new ReentrantLock(true); // fair optional
        private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);
        private static final ThreadLocal<Boolean> PREV_VALUE = new ThreadLocal<>();
        private static final UnsafeUtils UNSAFE = UnsafeUtils.INSTANCE;

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
                        UNSAFE.setStaticBooleanField(fIsInternationalBuildBoolean, true);
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
                            UNSAFE.setStaticBooleanField(fIsInternationalBuildBoolean, prev);
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
