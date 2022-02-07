package com.vade.evan;

/**
 * Vade JAVA Wrapper!
 */
public final class Vade {
    private Vade() {
    }

    public static native String ExecuteVade(String funcName, String[] arguments, String options, String config);
}
