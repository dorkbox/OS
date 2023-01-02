package dorkbox.os

internal object JVM {
    // java 8 cannot use JPMS. We use a multi-release jar to detect the state for java9+ runtimes

    /**
     * Returns true if the currently running JVM is using the classpath or modules (JPMS)
     */
    var usesJpms = false
}
