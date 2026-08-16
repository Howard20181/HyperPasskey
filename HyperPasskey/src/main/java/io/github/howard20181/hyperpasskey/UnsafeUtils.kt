package io.github.howard20181.hyperpasskey

import android.annotation.SuppressLint
import android.graphics.Point
import android.os.Build
import android.util.Log
import io.github.libxposed.api.XposedModule
import sun.misc.Unsafe
import java.lang.reflect.Field
import java.lang.reflect.Modifier

object UnsafeUtils {
    lateinit var xposedModule: XposedModule
        private set

    fun setXposedModule(module: XposedModule) {
        xposedModule = module
    }

    private val UNSAFE: Unsafe by lazy {
        @SuppressLint("DiscouragedPrivateApi")
        Unsafe::class.java.getDeclaredField("theUnsafe").let { field ->
            field.isAccessible = true
            field.get(null)
        } as Unsafe
    }
    private val HAS_STATIC_FINAL_RESTRICTION: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.CINNAMON_BUN
                || (Build.VERSION.SDK_INT == Build.VERSION_CODES.BAKLAVA
                && Build.VERSION.PREVIEW_SDK_INT > 0)
    private val fieldOffsetValue by lazy { getFieldOffsetOffset() }

    private fun hasStaticFinalRestriction(field: Field): Boolean {
        val staticFinal = Modifier.STATIC or Modifier.FINAL
        return HAS_STATIC_FINAL_RESTRICTION && (field.modifiers and staticFinal) == staticFinal
    }

    fun setStaticBooleanField(field: Field, value: Boolean) {
        if (hasStaticFinalRestriction(field)) {
            setStaticBoolean(
                field,
                value
            )
        } else {
            try {
                field.isAccessible = true
                field.setBoolean(null, value)
            } catch (e: IllegalAccessException) {
                xposedModule.log(
                    Log.WARN,
                    "UnsafeUtils",
                    "setStaticBooleanField failed and will use Unsafe",
                    e
                )
                setStaticBoolean(
                    field,
                    value
                )
            }
        }
    }

    private fun setStaticBoolean(field: Field, value: Boolean) {
        try {
            // Resolve the target field before reading its internal ART offset.
            field.isAccessible = true
            field.get(null)
        } catch (_: IllegalAccessException) {
        }

        val offset = UNSAFE.getInt(field, fieldOffsetValue).toLong()
        UNSAFE.putBoolean(field.declaringClass, offset, value)
    }

    fun setBooleanField(field: Field, obj: Any, value: Boolean) {
        if (hasStaticFinalRestriction(field)) {
            setBoolean(
                field,
                obj,
                value
            )
        } else {
            try {
                field.isAccessible = true
                field.setBoolean(obj, value)
            } catch (_: IllegalAccessException) {
                setBoolean(
                    field,
                    obj,
                    value
                )
            }
        }
    }

    fun setObjectField(field: Field, obj: Any, value: Any?) {
        if (hasStaticFinalRestriction(field)) {
            setObject(
                field,
                obj,
                value
            )
        } else {
            try {
                field.isAccessible = true
                field.set(obj, value)
            } catch (_: IllegalAccessException) {
                setObject(
                    field,
                    obj,
                    value
                )
            }
        }
    }

    private fun setBoolean(field: Field, obj: Any, value: Boolean) {
        try {
            // Resolve the target field before reading its internal ART offset.
            field.isAccessible = true
            field.getBoolean(obj)
        } catch (_: IllegalAccessException) {
        }
        val modifiers = field.modifiers
        val isVolatile = (modifiers and Modifier.VOLATILE) != 0
        val offset = UNSAFE.getInt(field, fieldOffsetValue).toLong()
        if ((modifiers and Modifier.STATIC) != 0) {
            UNSAFE.putBoolean(field.declaringClass, offset, value)
        } else {
            if (isVolatile) {
                putInt8Volatile(obj, offset, if (value) 1 else 0)
            } else {
                UNSAFE.putBoolean(obj, offset, value)
            }
        }
    }

    private fun setObject(field: Field, obj: Any, value: Any?) {
        try {
            // Resolve the target field before reading its internal ART offset.
            field.isAccessible = true
            field.get(obj)
        } catch (_: IllegalAccessException) {
        }
        val modifiers = field.modifiers
        val isVolatile = (modifiers and Modifier.VOLATILE) != 0
        val offset = UNSAFE.getInt(field, fieldOffsetValue).toLong()
        if ((modifiers and Modifier.STATIC) != 0) {
            UNSAFE.putObject(field.declaringClass, offset, value)
        } else {
            if (isVolatile) {
                UNSAFE.putObjectVolatile(obj, offset, value)
            } else {
                UNSAFE.putObject(obj, offset, value)
            }
        }
    }

    private fun putInt8Volatile(base: Any?, offset: Long, unsigned: Int) {
        val alignedOffset = offset and 3L.inv()
        var oldValue: Int
        var newValue: Int
        do {
            oldValue = UNSAFE.getIntVolatile(base, alignedOffset)
            val bits = (offset - alignedOffset).toInt() * 8
            newValue = (oldValue and (0xFF shl bits).inv()) or (unsigned shl bits)
        } while (!UNSAFE.compareAndSwapInt(base, alignedOffset, oldValue, newValue))
    }

    @Suppress("DEPRECATION")
    @SuppressLint("SoonBlockedPrivateApi")
    private fun getFieldOffsetOffset(): Long {
        var noSuchFieldException: NoSuchFieldException? = null
        try {
            val offsetField = Field::class.java.getDeclaredField("offset")
            offsetField.isAccessible = true
            offsetField.getInt(offsetField)
            return UNSAFE.objectFieldOffset(offsetField)
        } catch (e: NoSuchFieldException) {
            noSuchFieldException = e
        } catch (_: IllegalAccessException) {
        } catch (_: UnsupportedOperationException) {
        }

        val probeField = Point::class.java.getDeclaredField("x")
        probeField.getInt(Point())
        val fieldOffset = UNSAFE.objectFieldOffset(probeField).toInt()
        for (offset in 8 until 256 step 4) {
            val offsetLong = offset.toLong()
            if (UNSAFE.getInt(probeField, offsetLong) != fieldOffset) continue

            val modifiedOffset = fieldOffset.inv()
            UNSAFE.putInt(probeField, offsetLong, modifiedOffset)
            val currentOffset = UNSAFE.objectFieldOffset(probeField).toInt()
            UNSAFE.putInt(probeField, offsetLong, fieldOffset)
            if (currentOffset == modifiedOffset) return offsetLong
        }
        throw noSuchFieldException ?: NoSuchFieldException("Field.offset")
    }
}
