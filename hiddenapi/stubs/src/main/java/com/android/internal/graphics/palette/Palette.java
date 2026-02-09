package com.android.internal.graphics.palette;

import android.annotation.ColorInt;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.Px;
import android.graphics.Bitmap;

import androidx.annotation.RequiresApi;

import java.util.List;

public class Palette {
    @NonNull
    @RequiresApi(31)
    public static Builder from(@NonNull Bitmap bitmap, @NonNull Quantizer quantizer) {
        throw new UnsupportedOperationException("STUB");
    }

    /**
     * Start generating a {@link Palette} with the returned {@link Palette.Builder} instance.
     */
    public static Palette.Builder from(Bitmap bitmap) {
        throw new UnsupportedOperationException("STUB");
    }

    /**
     * Generate a {@link Palette} from the pre-generated list of {@link Palette.Swatch} swatches.
     * This
     * is useful for testing, or if you want to resurrect a {@link Palette} instance from a list of
     * swatches. Will return null if the {@code swatches} is null.
     */
    @NonNull
    public static Palette from(@NonNull List<Swatch> swatches) {
        throw new UnsupportedOperationException("STUB");
    }


    @Nullable
    public Swatch getDominantSwatch() {
        throw new UnsupportedOperationException("STUB");
    }

    /**
     * Returns all of the swatches which make up the palette.
     */
    @NonNull
    public List<Swatch> getSwatches() {
        throw new UnsupportedOperationException("STUB");
    }

    public static class Builder {
        @NonNull
        public Palette.Builder setQuantizer(Quantizer quantizer) {
            throw new UnsupportedOperationException("STUB");
        }

        @NonNull
        public Builder setRegion(@Px int left, @Px int top, @Px int right, @Px int bottom) {
            throw new UnsupportedOperationException("STUB");
        }

        @NonNull
        public Builder maximumColorCount(int colors) {
            throw new UnsupportedOperationException("STUB");
        }

        @NonNull
        public Builder resizeBitmapArea(int area) {
            throw new UnsupportedOperationException("STUB");
        }

        @NonNull
        public Palette generate() {
            throw new UnsupportedOperationException("STUB");
        }
    }

    public static class Swatch {
        @ColorInt
        @RequiresApi(31)
        public int getInt() {
            throw new UnsupportedOperationException("STUB");
        }

        /**
         * @return this swatch's RGB color value
         */
        @ColorInt
        public int getRgb() {
            throw new UnsupportedOperationException("STUB");
        }

        /**
         * @return the number of pixels represented by this swatch
         */
        public int getPopulation() {
            throw new UnsupportedOperationException("STUB");
        }
    }

    /**
     * A Filter provides a mechanism for exercising fine-grained control over which colors
     * are valid within a resulting {@link Palette}.
     */
    public interface Filter {
    }
}
