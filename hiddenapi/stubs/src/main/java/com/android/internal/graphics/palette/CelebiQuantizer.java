package com.android.internal.graphics.palette;

import androidx.annotation.RequiresApi;

import java.util.List;

@RequiresApi(31)
public class CelebiQuantizer implements Quantizer {
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
