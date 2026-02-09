package com.android.internal.graphics;

import android.annotation.ColorInt;
import android.annotation.NonNull;

public class ColorUtils {
    /**
     * 254       * Convert the ARGB color to its HSL (hue-saturation-lightness) components.
     * 255       * <ul>
     * 256       * <li>outHsl[0] is Hue [0 .. 360)</li>
     * 257       * <li>outHsl[1] is Saturation [0...1]</li>
     * 258       * <li>outHsl[2] is Lightness [0...1]</li>
     * 259       * </ul>
     * 260       *
     * 261       * @param color  the ARGB color to convert. The alpha component is ignored
     * 262       * @param outHsl 3-element array which holds the resulting HSL components
     * 263
     */
    public static void colorToHSL(@ColorInt int color, @NonNull float[] outHsl) {
        throw new UnsupportedOperationException("Stub!");
    }
}
