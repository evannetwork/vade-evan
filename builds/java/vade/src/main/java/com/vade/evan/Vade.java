package com.vade.evan;

/**
 * Vade JAVA Wrapper!
 */
public final class Vade {
    private Vade() {
    }

    static {
        System.loadLibrary("vade_evan");
    }

    public static native String executeVade(String funcName, String[] arguments, String options, String config);
}
