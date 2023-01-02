package dorkbox.os

internal object JVM {
    /**
     * Returns true if the currently running JVM is using the classpath or modules (JPMS)
     */
    var usesJpms = true == java.lang.ModuleLayer.boot().findModule("java.desktop").isPresent
}
