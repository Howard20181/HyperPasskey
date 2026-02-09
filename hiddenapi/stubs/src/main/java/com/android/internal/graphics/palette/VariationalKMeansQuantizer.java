package com.android.internal.graphics.palette;

import java.util.List;

public class VariationalKMeansQuantizer implements Quantizer {
    @Override
    public void quantize(int[] pixels, int maxColors) {
        throw new UnsupportedOperationException("STUB");
    }

    @Override
    public void quantize(int[] pixels, int maxColors, Palette.Filter[] filters) {
        throw new UnsupportedOperationException("STUB");
    }

    @Override
    public List<Palette.Swatch> getQuantizedColors() {
        throw new UnsupportedOperationException("STUB");
    }
}
