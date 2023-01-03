/*
 * Copyright 2022 dorkbox, llc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("unused", "SameParameterValue", "MemberVisibilityCanBePrivate", "LocalVariableName")

package dorkbox.os

import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.security.AccessController
import java.security.PrivilegedAction
import java.util.*
import java.util.concurrent.*

object OS {
    /**
     * Gets the version number.
     */
    const val version = "1.3"

    init {
        // Add this project to the updates system, which verifies this class + UUID + version information
        dorkbox.updates.Updates.add(OS::class.java, "a2afbd7d98084a9eb6eb663570dbec77", version)
    }

    // make the default unix
    val LINE_SEPARATOR = getProperty("line.separator", "\n")

    const val LINE_SEPARATOR_UNIX = "\n"
    const val LINE_SEPARATOR_MACOS = "\r"
    const val LINE_SEPARATOR_WINDOWS = "\r\n"

    val TEMP_DIR = File(getProperty("java.io.tmpdir", "temp")).absoluteFile

    /**
     * The currently running MAJOR java version as a NUMBER. For example, "Java version 1.7u45", and converts it into 7, uses JEP 223 for java > 9
     */
    val javaVersion: Int by lazy {
        // We are >= java 10, use JEP 223 to get the version (early releases of 9 might not have JEP 223, so 10 is guaranteed to have it)
        var fullJavaVersion = getProperty("java.version", "9")
        if (fullJavaVersion.startsWith("1.")) {
            when (fullJavaVersion[2]) {
                '4' -> 4
                '5' -> 5
                '6' -> 6
                '7' -> 7
                '8' -> 8
                '9' -> 9
                else -> 8
            }
        } else {
            fullJavaVersion = getProperty("java.specification.version", "10")

            try {
                // it will ALWAYS be the major release version as an integer. See http://openjdk.java.net/jeps/223
                fullJavaVersion.toInt()
            } catch (ignored: Exception) {
                // the last valid guess we have, since the current Java implementation, whatever it is, decided not to cooperate with JEP 223.
                8
            }
        }
    }

    /**
     * Returns true if the currently running JVM is using the classpath or modules (JPMS)
     */
    val usesJpms = JVM.usesJpms

    /**
     * Returns the *ORIGINAL* system time zone, before (*IF*) it was changed to UTC
     */
    val originalTimeZone = TimeZone.getDefault().id!!

    /**
     * JVM reported osName, the default (if there is none detected) is 'linux'
     */
    val osName = getProperty("os.name", "linux").lowercase()

    /**
     * JVM reported osArch, the default (if there is none detected) is 'amd64'
     */
    val osArch = getProperty("os.arch", "amd64").lowercase()

    /**
     * @return the optimum number of threads for a given task. Makes certain not to take ALL the threads, always returns at least one
     * thread.
     */
    val optimumNumberOfThreads = (Runtime.getRuntime().availableProcessors() - 2).coerceAtLeast(1)

    /**
     * The determined OS type
     */
    val type: OSType by lazy {
        if (osName.startsWith("linux")) {
            // best way to determine if it's android.
            // Sometimes java binaries include Android classes on the classpath, even if it isn't actually Android, so we check the VM
            val isAndroid = "Dalvik" == getProperty("java.vm.name", "")
            if (isAndroid) {
                // android check from https://stackoverflow.com/questions/14859954/android-os-arch-output-for-arm-mips-x86
                when (osArch) {
                    "armeabi" -> {
                        OSType.AndroidArm56 // old/low-end non-hf 32bit cpu
                    }
                    "armeabi-v7a" -> {
                        OSType.AndroidArm7 // 32bit hf cpu
                    }
                    "arm64-v8a" -> {
                        OSType.AndroidArm8  // 64bit hf cpu
                    }
                    "x86" -> {
                        OSType.AndroidX86 // 32bit x86 (usually emulator)
                    }
                    "x86_64" -> {
                        OSType.AndroidX86_64 // 64bit x86 (usually emulator)
                    }
                    "mips" -> {
                        OSType.AndroidMips // 32bit mips
                    }
                    "mips64" -> {
                        OSType.AndroidMips64  // 64bit mips
                    }
                    else -> {
                        throw java.lang.RuntimeException("Unable to determine OS type for $osName $osArch")
                    }
                }
            } else {
                // http://mail.openjdk.java.net/pipermail/jigsaw-dev/2017-April/012107.html
                when(osArch) {
                    "i386", "x86" -> {
                        OSType.Linux32
                    }
                    "arm" -> {
                        OSType.LinuxArm32
                    }

                    "x86_64", "amd64" -> {
                        OSType.Linux64
                    }
                    "aarch64" -> {
                        OSType.LinuxArm64
                    }
                    else -> {
                        when {
                            // oddballs (android usually)
                            osArch.startsWith("arm64") -> {
                                OSType.LinuxArm64
                            }
                            osArch.startsWith("arm") -> {
                                if (osArch.contains("v8")) {
                                    OSType.LinuxArm64
                                } else {
                                    OSType.LinuxArm32
                                }
                            }
                            else -> {
                                throw java.lang.RuntimeException("Unable to determine OS type for $osName $osArch")
                            }
                        }
                    }
                }
            }
        } else if (osName.startsWith("windows")) {
            if ("amd64" == osArch) {
                OSType.Windows64
            } else {
                OSType.Windows32
            }
        } else if (osName.startsWith("mac") || osName.startsWith("darwin")) {
            when (osArch) {
                "x86_64" -> {
                    OSType.MacOsX64
                }
                "aarch64" -> {
                    OSType.MacOsArm
                }
                else -> {
                    OSType.MacOsX32  // new macOS is no longer 32 bit, but just in case.
                }
            }
        } else if (osName.startsWith("freebsd") ||
            osName.contains("nix") ||
            osName.contains("nux") ||
            osName.startsWith("aix")) {
            when (osArch) {
                "x86", "i386" -> {
                    OSType.Unix32
                }
                "arm" -> {
                    OSType.UnixArm
                }
                else -> {
                    OSType.Unix64
                }
            }
        } else if (osName.startsWith("solaris") ||
            osName.startsWith("sunos")) {
            OSType.Solaris
        } else {
            throw java.lang.RuntimeException("Unable to determine OS type for $osName $osArch")
        }
    }

    init {
        if (!TEMP_DIR.isDirectory) {
            // create the temp dir if necessary because the TEMP dir doesn't exist.
            TEMP_DIR.mkdirs()
        }

        /*
         * By default, the timer resolution on Windows ARE NOT high-resolution (16ms vs 1ms)
         *
         * 'Thread.sleep(1)' will not really sleep for 1ms, but will really sleep for ~16ms. This long-running sleep will trick Windows
         *  into using higher resolution timers.
         *
         * See: https://bugs.java.com/bugdatabase/view_bug.do?bug_id=6435126
         */
        if (type.isWindows) {
            // only necessary on windows
            val timerAccuracyThread = Thread(
            {
                 while (true) {
                     try {
                         Thread.sleep(Long.MAX_VALUE)
                     } catch (ignored: Exception) {
                     }
                 }
            }, "FixWindowsHighResTimer")
            timerAccuracyThread.isDaemon = true
            timerAccuracyThread.start()
        }
    }

    /**
     * @return the value of the Java system property with the specified `property`, or null if it does not exist.
     */
    fun getProperty(property: String): String? {
        return try {
            if (System.getSecurityManager() == null) {
                System.getProperty(property, null)
            } else {
                AccessController.doPrivileged(PrivilegedAction { System.getProperty(property, null) })
            }
        } catch (ignored: Exception) {
            null
        }
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getProperty(property: String, defaultValue: String): String {
        return try {
            if (System.getSecurityManager() == null) {
                System.getProperty(property, defaultValue)
            } else {
                AccessController.doPrivileged(PrivilegedAction { System.getProperty(property, defaultValue) })
            }
        } catch (ignored: Exception) {
            defaultValue
        }
    }

    /**
     * @return the System Environment property in a safe way for a given property, or null if it does not exist.
     */
    fun getEnv(): Map<String, String> {
        return try {
            if (System.getSecurityManager() == null) {
                System.getenv()
            } else {
                AccessController.doPrivileged(PrivilegedAction { System.getenv() })
            }
        } catch (ignored: Exception) {
            mapOf()
        }
    }

    /**
     * @return the System Environment property in a safe way for a given property, or null if it does not exist.
     */
    fun getEnv(property: String): String? {
        return try {
            if (System.getSecurityManager() == null) {
                System.getenv(property)
            } else {
                AccessController.doPrivileged(PrivilegedAction { System.getenv(property) })
            }
        } catch (ignored: Exception) {
            null
        }
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getEnv(property: String, defaultValue: String): String {
        return getEnv(property) ?: defaultValue
    }


    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getBoolean(property: String, defaultValue: Boolean): Boolean {
        var value = getProperty(property) ?: return defaultValue
        value = value.trim { it <= ' ' }.lowercase(Locale.getDefault())
        if (value.isEmpty()) {
            return defaultValue
        }

        if ("false" == value || "no" == value || "0" == value) {
            return false
        }

        return if ("true" == value || "yes" == value || "1" == value) {
            true
        } else defaultValue
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getInt(property: String, defaultValue: Int): Int {
        var value = getProperty(property) ?: return defaultValue
        value = value.trim { it <= ' ' }

        try {
            return value.toInt()
        } catch (ignored: Exception) {
        }
        return defaultValue
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getLong(property: String, defaultValue: Long): Long {
        var value = getProperty(property) ?: return defaultValue
        value = value.trim { it <= ' ' }

        try {
            return value.toLong()
        } catch (ignored: Exception) {
        }
        return defaultValue
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getFloat(property: String, defaultValue: Float): Float {
        var value = getProperty(property) ?: return defaultValue
        value = value.trim { it <= ' ' }

        try {
            return value.toFloat()
        } catch (ignored: Exception) {
        }
        return defaultValue
    }

    /**
     * @return the value of the Java system property with the specified `property`, while falling back to the
     * specified default value if the property access fails.
     */
    fun getDouble(property: String, defaultValue: Double): Double {
        var value = getProperty(property) ?: return defaultValue
        value = value.trim { it <= ' ' }

        try {
            return value.toDouble()
        } catch (ignored: Exception) {
        }
        return defaultValue
    }



    val is32bit = type.is32bit
    val is64bit = type.is64bit

    /**
     * @return true if this is x86/x64/arm architecture (intel/amd/etc) processor.
     */
    val isX86 = type.isX86
    val isMips = type.isMips
    val isArm = type.isArm


    val isLinux = type.isLinux
    val isUnix = type.isUnix
    val isSolaris = type.isSolaris
    val isWindows = type.isWindows
    val isMacOsX = type.isMacOsX
    val isAndroid = type.isAndroid

    /**
     * Set our system to UTC time zone. Retrieve the **original** time zone via [.getOriginalTimeZone]
     */
    fun setUTC() {
        // have to set our default timezone to UTC. EVERYTHING will be UTC, and if we want local, we must explicitly ask for it.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
    }

    /**
     * @return the first line of the exception message from 'throwable', or the type if there was no message.
     */
    fun getExceptionMessage(throwable: Throwable): String? {
        var message = throwable.message
        if (message != null) {
            val index = message.indexOf(LINE_SEPARATOR)
            if (index > -1) {
                message = message.substring(0, index)
            }
        } else {
            message = throwable.javaClass.simpleName
        }
        return message
    }

    /**
     * Executes the given command and returns its output.
     *
     * This is based on an aggregate of the answers provided here: [https://stackoverflow.com/questions/35421699/how-to-invoke-external-command-from-within-kotlin-code]
     */
    private fun execute(vararg args: String, timeout: Long = 60): String {
        return ProcessBuilder(args.toList())
            .redirectOutput(ProcessBuilder.Redirect.PIPE)
            .redirectError(ProcessBuilder.Redirect.PIPE)
            .start()
            .apply { waitFor(timeout, TimeUnit.SECONDS) }
            .inputStream.bufferedReader().readText().trim()
    }

    // true if the exit code is 0 (meaning standard exit)
    private fun executeStatus(vararg args: String, timeout: Long = 60): Boolean {
        return ProcessBuilder(args.toList())
            .redirectOutput(ProcessBuilder.Redirect.PIPE)
            .redirectError(ProcessBuilder.Redirect.PIPE)
            .start()
            .apply { waitFor(timeout, TimeUnit.SECONDS) }
            .exitValue() == 0
    }

    object Windows {
        /**
         * Version info at release.
         ```
          https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions

          Windows XP                    5.1.2600  (2001-10-25)
          Windows Server 2003           5.2.3790  (2003-04-24)

          Windows Home Server           5.2.3790  (2007-06-16)

          -------------------------------------------------

          Windows Vista                 6.0.6000  (2006-11-08)
          Windows Server 2008 SP1       6.0.6001  (2008-02-27)
          Windows Server 2008 SP2	    6.0.6002  (2009-04-28)

          -------------------------------------------------

          Windows 7                     6.1.7600  (2009-10-22)
          Windows Server 2008 R2        6.1.7600  (2009-10-22)
          Windows Server 2008 R2 SP1    6.1.7601  (?)

          Windows Home Server 2011      6.1.8400  (2011-04-05)

          -------------------------------------------------

          Windows 8                     6.2.9200  (2012-10-26)
          Windows Server 2012	        6.2.9200  (2012-09-04)

          -------------------------------------------------

          Windows 8.1                   6.3.9600  (2013-10-18)
          Windows Server 2012 R2        6.3.9600  (2013-10-18)

          -------------------------------------------------

          Windows 10	                10.0.10240  (2015-07-29)
          Windows 10	                10.0.10586  (2015-11-12)
          Windows 10	                10.0.14393  (2016-07-18)

          Windows Server 2016           10.0.14393  (2016-10-12)
          Windows Server 2019 	      	10.0.17763  (2018-10-02)
          Windows Server 2022 	        10.0.20348  (2021-08-18)

          Windows 11 Original Release 	10.0.22000  (2021-10-05)
          Windows 11 2022 Update        10.0.22621  (2022-09-20)
        ```
         * @return the {major}{minor} version of windows, ie: Windows Version 10.0.10586 -> {10}{0}
         */
        val version: IntArray by lazy {
            if (!isWindows) {
                intArrayOf(0, 0)
            } else {
                val version = IntArray(2)

                try {
                    val output = getProperty("os.version")
                    if (output != null) {
                        val split = output.split("\\.").dropLastWhile { it.isEmpty() }.toTypedArray()
                        if (split.size <= 2) {
                            for (i in split.indices) {
                                version[i] = split[i].toInt()
                            }
                        }
                    }
                } catch (ignored: Throwable) {
                }
                version
            }
        }

        /**
         * @return is Windows XP or equivalent
         */
        val isWindowsXP = version[0] == 5

        /**
         * @return is Windows Vista or equivalent
         */
        val isWindowsVista = version[0] == 6 && version[1] == 0

        /**
         * @return is Windows 7 or equivalent
         */
        val isWindows7 = version[0] == 6 && version[1] == 1

        /**
         * @return is Windows 8 or equivalent
         */
        val isWindows8 = version[0] == 6 && version[1] == 2

        /**
         * @return is Windows 8.1 or equivalent
         */
        val isWindows8_1 = version[0] == 6 && version[1] == 3

        /**
         * @return is greater than or equal to Windows 8.1 or equivalent
         */
        val isWindows8_1_plus: Boolean by lazy {
            val version = version
            if (version[0] == 6 && version[1] >= 3) {
                true
            } else {
                version[0] > 6
            }
        }

        /**
         * @return is Windows 10 or equivalent
         */
        val isWindows10 = version[0] == 10

        /**
         * @return is Windows 10 or greater
         */
        val isWindows10_plus = version[0] >= 10

        /**
         * @return is Windows 11 (original release was 21H2)
         */
        val isWindows11 = version[0] == 10 && version[1] == 0 && version[2] >= 22000

        /**
         * @return is Windows 11 update 22H2
         */
        val isWindows11_22H2 = version[0] == 10 && version[1] == 0 && version[2] >= 22621
    }

    object Unix {
        // uname
        val isFreeBSD: Boolean by lazy {
            if (!isUnix) {
                false
            } else {
                try {
                    // uname
                    execute("uname").startsWith("FreeBSD")
                } catch (ignored: Throwable) {
                    false
                }
            }
        }
    }

    object Linux {
        // NAME="Arch Linux"
        // PRETTY_NAME="Arch Linux"
        // ID=arch
        // ID_LIKE=archlinux
        // ANSI_COLOR="0;36"
        // HOME_URL="https://www.archlinux.org/"
        // SUPPORT_URL="https://bbs.archlinux.org/"
        // BUG_REPORT_URL="https://bugs.archlinux.org/"

        // similar on other distro's.  ID is always the "key" to the distro
        // this is likely a file we are interested in.// looking for files like /etc/os-release

        /**
         * @return os release info or ""
         */
        val info: String by lazy {
            if (!isLinux) {
                ""
            } else {
                var data = ""
                try {
                    val releaseFiles: MutableList<File> = LinkedList()
                    var totalLength = 0

                    // looking for files like /etc/os-release
                    val file = File("/etc")
                    if (file.isDirectory) {
                        val list = file.listFiles()
                        if (list != null) {
                            for (f in list) {
                                if (f.isFile && f.name.contains("release")) {
                                    // this is likely a file we are interested in.
                                    releaseFiles.add(f)
                                    totalLength += file.length().toInt()
                                }
                            }
                        }
                    }

                    if (totalLength > 0) {
                        val fileContents = StringBuilder(totalLength)
                        for (releaseFile in releaseFiles) {
                            BufferedReader(FileReader(releaseFile)).use { reader ->
                                var currentLine: String?

                                // NAME="Arch Linux"
                                // PRETTY_NAME="Arch Linux"
                                // ID=arch
                                // ID_LIKE=archlinux
                                // ANSI_COLOR="0;36"
                                // HOME_URL="https://www.archlinux.org/"
                                // SUPPORT_URL="https://bbs.archlinux.org/"
                                // BUG_REPORT_URL="https://bugs.archlinux.org/"

                                // similar on other distro's.  ID is always the "key" to the distro
                                while (reader.readLine().also { currentLine = it } != null) {
                                    fileContents.append(currentLine).append(LINE_SEPARATOR_UNIX)
                                }
                            }
                        }
                        data = fileContents.toString()
                    }
                } catch (ignored: Throwable) {
                }

                data
            }
        }


        /**
         * @param id the info ID to check, ie: ubuntu, arch, debian, etc... This is what the OS vendor uses to ID their OS.
         *
         * @return true if this OS is identified as the specified ID.
         */
        fun isReleaseType(id: String): Boolean {
            // also matches on 'DISTRIB_ID' and 'VERSION_ID'
            // ID=linuxmint/fedora/arch/ubuntu/etc
            return info.contains("ID=$id\n")
        }

        val isArch: Boolean by lazy {
            isReleaseType("arch")
        }

        val isDebian: Boolean by lazy {
            isReleaseType("debian")
        }

        val isElementaryOS: Boolean by lazy {
            try {
                // ID="elementary"  (notice the extra quotes)
                info.contains("ID=\"elementary\"\n") || info.contains("ID=elementary\n") ||

                        // this is specific to eOS < 0.3.2
                        info.contains("ID=\"elementary OS\"\n")
            } catch (ignored: Throwable) {
                false
            }
        }

        val isFedora: Boolean by lazy {
            isReleaseType("fedora")
        }

        val fedoraVersion: Int by lazy {
            if (!isFedora) {
                0
            } else {
                try {
                    // ID=fedora
                    if (info.contains("ID=fedora\n")) {
                        // should be: VERSION_ID=23\n  or something
                        val beginIndex = info.indexOf("VERSION_ID=") + 11
                        val fedoraVersion_ = info.substring(beginIndex, info.indexOf(LINE_SEPARATOR_UNIX, beginIndex))
                        fedoraVersion_.toInt()
                    } else {
                        0
                    }
                } catch (ignored: Throwable) {
                    0
                }
            }
        }

        val isLinuxMint: Boolean by lazy {
            isReleaseType("linuxmint")
        }

        val isUbuntu: Boolean by lazy {
            isReleaseType("ubuntu")
        }

        val ubuntuVersion: IntArray by lazy {
            @Suppress("DuplicatedCode")
            if (!isUbuntu) {
                intArrayOf(0, 0)
            } else if (distribReleaseInfo != null) {
                val split = distribReleaseInfo!!.split("\\.").toTypedArray()
                intArrayOf(split[0].toInt(), split[1].toInt())
            } else {
                intArrayOf(0, 0)
            }
        }

        val elementaryOSVersion: IntArray by lazy {
            // 0.1 Jupiter. The first stable version of elementary OS was Jupiter, published on 31 March 2011 and based on Ubuntu 10.10. ...
            // 0.2 Luna. elementary OS 0.2 "Luna" ...
            // 0.3 Freya. elementary OS 0.3 "Freya" ...
            // 0.4 Loki. elementary OS 0.4, known by its codename, "Loki", was released on 9 September 2016. ...
            // 5.0 Juno

            @Suppress("DuplicatedCode")
            if (!isElementaryOS) {
                intArrayOf(0, 0)
            } else if (distribReleaseInfo != null) {
                val split = distribReleaseInfo!!.split("\\.").toTypedArray()
                intArrayOf(split[0].toInt(), split[1].toInt())
            } else {
                intArrayOf(0, 0)
            }
        }

        val isKali: Boolean by lazy {
            isReleaseType("kali")
        }

        val isPop: Boolean by lazy {
            isReleaseType("pop")
        }

        val isIgel: Boolean by lazy {
            isReleaseType("IGEL")
        }

        /**
         * @return the `DISTRIB_RELEASE` info as a String, if possible. Otherwise NULL
         */
        val distribReleaseInfo: String? by lazy {
            val releaseString = "DISTRIB_RELEASE="
            var index = info.indexOf(releaseString)
            var data: String? = null

            try {
                if (index > -1) {
                    index += releaseString.length
                    val newLine = info.indexOf(LINE_SEPARATOR_UNIX, index)
                    if (newLine > index) {
                        data = info.substring(index, newLine)
                    }
                }
            } catch (ignored: Throwable) {
            }

            data
        }


        val isWSL: Boolean by lazy {
            try {
                // looking for /proc/version
                val file = File("/proc/version")
                var data: Boolean? = null
                if (file.canRead()) {
                    try {
                        val msString: Boolean
                        BufferedReader(FileReader(file)).use { reader ->
                            // Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com) (gcc version 5.4.0 (GCC) ) #488-Microsoft Mon Sep 01 13:43:00 PST 2020
                            msString = reader.readLine().contains("-Microsoft")
                        }

                        data = msString
                    } catch (ignored: Throwable) {
                    }
                }

                if (data == null) {
                    // reading the file didn't work for whatever reason...
                    // uname -v
                    data = execute("uname", "-v").contains("-Microsoft")
                }

                if (data == true) {
                    data
                } else {
                    false
                }
            } catch (ignored: Throwable) {
                false
            }
        }

        val isRoot: Boolean by lazy {
            // this means we are running as sudo
            var isSudoOrRoot = System.getenv("SUDO_USER") != null

            if (!isSudoOrRoot) {
                // running as root (also can be "sudo" user). A lot slower that checking a sys env, but this is guaranteed to work
                try {
                    // id -u
                    isSudoOrRoot = "0" == execute("id", "-u")
                } catch (ignored: Throwable) {
                }
            }
            isSudoOrRoot
        }

        object PackageManager {
            enum class Type(val installString: String) {
                APT("apt install"),
                APTGET("apt-get install"),
                YUM("yum install"),
                PACMAN("pacman -S ");
            }

            val type: Type by lazy {
                if (File("/usr/bin/apt").canExecute()) {
                    Type.APT
                } else if (File("/usr/bin/apt-get").canExecute()) {
                    Type.APTGET
                } else if (File("/usr/bin/yum").canExecute()) {
                    Type.YUM
                } else if (File("/usr/bin/pacman").canExecute()) {
                    Type.PACMAN
                } else {
                    Type.APTGET
                }

                // default is apt-get, even if it isn't correct
            }

            /**
             * @return true if the package is installed
             */
            fun isPackageInstalled(packageName: String): Boolean {
                // dpkg
                // dpkg -L libappindicator3
                // dpkg-query: package 'libappindicator3' is not installed
                val is_dpkg = File("/usr/bin/dpkg").canExecute()
                if (is_dpkg) {
                    return !execute("dpkg", "-L", packageName).contains("is not installed")
                }

                // rpm
                // rpm -q libappindicator234
                // package libappindicator234 is not installed
                val is_rpm = File("/usr/bin/rpm").canExecute()
                if (is_rpm) {
                    return !execute("rpm", "-q", packageName).contains("is not installed")
                }


                // pacman
                // pacman -Qi <packageName>
                val is_pacmac = File("/usr/bin/pacman").canExecute()
                if (is_pacmac) {
                    try {
                        // use the exit code to determine if the packages exists on the system
                        // 0 the package exists, 1 it doesn't
                        return executeStatus("pacman", "-Qi", packageName)

                        //return start == 0
                    } catch (ignored: Exception) {
                    }
                }

                return false
            }
        }
    }

    object DesktopEnv {
        enum class Env {
            Gnome, KDE, Unity, Unity7, XFCE, LXDE, MATE, Pantheon, ChromeOS, Unknown
        }

        enum class EnvType {
            X11, WAYLAND, Unknown
        }

        private fun isValidCommand(partialExpectationInOutput: String, commandOutput: String): Boolean {
            return (commandOutput.contains(partialExpectationInOutput) &&
                    !commandOutput.contains("not installed") &&
                    !commandOutput.contains("No such file or directory"))
        }

        // have no idea how this can happen....
        val type: EnvType by lazy {
            when (getEnv("XDG_SESSION_TYPE")) {
                "x11" -> {
                    EnvType.X11
                }
                "wayland" -> {
                    EnvType.WAYLAND
                }
                else -> {
                    EnvType.Unknown
                }
            }
        }

        val isX11 = type == EnvType.X11
        val isWayland = type == EnvType.WAYLAND


        val isMATE: Boolean by lazy {
            if (!isLinux && !isUnix) {
                false
            } else {
                try {
                    File("/usr/bin/mate-about").exists()
                } catch (ignored: Throwable) {
                    false
                }
            }
        }

        val isGnome: Boolean by lazy {
            System.err.println("1")
            if (!isLinux && !isUnix) {
                System.err.println("2")
                false
            } else {
                System.err.println("3")
                try {
                    // note: some versions of linux can ONLY access "ps a"; FreeBSD and most linux is "ps x"
                    // we try "x" first

                    // ps x | grep gnome-shell
                    var contains = execute("ps", "x").contains("gnome-shell")
                    if (!contains && isLinux) {
                        // only try again if we are linux

                        // ps a | grep gnome-shell
                        contains = execute("ps", "a").contains("gnome-shell")
                    }
                    contains
                } catch (ignored: Throwable) {
                    false
                }
            }
        }

        /**
         * @return a string representing the current gnome-shell version, or NULL if it could not be found
         */
        val gnomeVersion: String? by lazy {
            if (!isLinux && !isUnix) {
                null
            } else {
                try {
                    // gnome-shell --version
                    val versionString = execute("gnome-shell", "--version")
                    if (versionString.isNotEmpty()) {
                        // GNOME Shell 3.14.1
                        val version = versionString.replace("[^\\d.]".toRegex(), "")
                        if (version.isNotEmpty() && version.indexOf('.') > 0) {
                            // should just be 3.14.1 or 3.20 or similar
                            version
                        } else {
                            null
                        }
                    } else {
                        null
                    }
                } catch (ignored: Throwable) {
                    null
                }
            }
        }

        // Check if plasmashell is running, if it is -- then we are most likely KDE
        val isKDE: Boolean by lazy {
            val XDG = getEnv("XDG_CURRENT_DESKTOP")
            if (XDG == null) {
                // Check if plasmashell is running, if it is -- then we are most likely KDE
                val plasmaVersion = plasmaVersion
                plasmaVersion > 0
            } else {
                "kde".equals(XDG, ignoreCase = true)
            }
        }

        /**
         * The full version number of plasma shell (if running) as a String.
         *
         * @return cannot represent '5.6.5' as a number, so we return a String instead or NULL if unknown
         */
        val plasmaVersionFull: String? by lazy {
            if (!isLinux && !isUnix) {
                null
            } else {
                try {
                    // plasma-desktop -v
                    // plasmashell --version
                    val output = execute("plasmashell", "--version")
                    if (output.isNotEmpty()) {
                        // DEFAULT icon size is 16. KDE is bananas on what they did with tray icon scale
                        // should be: plasmashell 5.6.5   or something
                        val s = "plasmashell "
                        if (isValidCommand(s, output)) {
                            output.substring(output.indexOf(s) + s.length)
                        } else {
                            null
                        }
                    } else {
                        null
                    }
                } catch (ignored: Throwable) {
                    null
                }
            }
        }

        /**
         * The first two decimal places of the version number of plasma shell (if running) as a double.
         *
         * @return cannot represent '5.6.5' as a number, so we return just the first two decimal places instead
         */
        val plasmaVersion: Double by lazy {
            if (plasmaVersionFull == null || plasmaVersionFull!!.startsWith("0")) {
                0.0
            } else {
                // this isn't the BEST way to do this, but it's simple and easy to understand
                val split = plasmaVersionFull!!.split("\\.", limit = 3).toTypedArray()
                if (split.size > 2) {
                    (split[0] + "." + split[1]).toDouble()
                } else {
                    split[0].toDouble()
                }
            }
        }

        val isXfce: Boolean by lazy {
            if (!isLinux && !isUnix) {
                false
            } else {
                try {
                    // note: some versions of linux can ONLY access "ps a"; FreeBSD and most linux is "ps x"
                    // we try "x" first

                    // ps x | grep xfce
                    var contains = execute("ps", "x").contains("xfce")
                    if (!contains && isLinux) {
                        // only try again if we are linux

                        // ps a | grep gnome-shell
                        contains = execute("ps", "a").contains("xfce")
                    }
                    contains
                } catch (ignored: Throwable) {
                    false
                }
            }
        }

        /**
         * There are sometimes problems with nautilus (the file browser) and some GTK methods. It is ridiculous for me to have to
         * work around their bugs like this.
         *
         * see: https://askubuntu.com/questions/788182/nautilus-not-opening-up-showing-glib-error
         */
        val isNautilus: Boolean by lazy {
            if (!isLinux && !isUnix) {
                false
            } else {
                try {
                    // nautilus --version
                    val output = execute("nautilus", "--version")
                    if (output.isNotEmpty()) {
                        // should be: GNOME nautilus 3.14.3   or something
                        val s = "GNOME nautilus "
                        isValidCommand(s, output)
                    } else {
                        false
                    }
                } catch (ignored: Throwable) {
                    false
                }
            }
        }

        val isChromeOS: Boolean by lazy {
            if (!isLinux) {
                false
            } else {
                try {
                    // ps aux | grep chromeos
                    execute("ps", "aux").contains("chromeos")
                } catch (ignored: Throwable) {
                    false
                }
            }
        }

        /**
         * @param channel which XFCE channel to query. Cannot be null
         * @param property which property (in the channel) to query. Null will list all properties in the channel
         *
         * @return the property value or "".
         */
        fun queryXfce(channel: String, property: String?): String {
            if (!isLinux && !isUnix) {
                return ""
            }
            try {
                // xfconf-query -c xfce4-panel -l
                val commands: MutableList<String> = ArrayList()
                commands.add("xfconf-query")
                commands.add("-c")
                commands.add(channel)
                if (property != null) {
                    // get property for channel
                    commands.add("-p")
                    commands.add(property)
                } else {
                    // list all properties for the channel
                    commands.add("-l")
                }

                return execute(*commands.toTypedArray())
            } catch (ignored: Throwable) {
                return ""
            }
        }

        val env: Env by lazy {
            // if we are running as ROOT, we *** WILL NOT *** have access to  'XDG_CURRENT_DESKTOP'
            //   *unless env's are preserved, but they are not guaranteed to be
            // see:  http://askubuntu.com/questions/72549/how-to-determine-which-window-manager-is-running
            var XDG = getEnv("XDG_CURRENT_DESKTOP")
            if (XDG == null) {
                // maybe we are running as root???
                XDG = "unknown" // try to autodetect if we should use app indicator or gtkstatusicon
            }

            // Ubuntu 17.10+ is special ... this is ubuntu:GNOME (it now uses wayland instead of x11, so many things have changed...)
            // So it's gnome, and gnome-shell, but with some caveats
            // see: https://bugs.launchpad.net/ubuntu/+source/gnome-shell/+bug/1700465

            // BLEH. if gnome-shell is running, IT'S REALLY GNOME!
            // we must ALWAYS do this check!!
            if (isGnome) {
                XDG = "gnome"
            } else if (isKDE) {
                // same thing with plasmashell!
                XDG = "kde"
            } else if (isXfce) {
                // https://github.com/dorkbox/SystemTray/issues/100
                // IGEL linux doesn't say what it is... but we know it's XFCE ... EVEN THOUGH it reports X11!!
                XDG = "xfce"
            }

            if ("unity".equals(XDG, ignoreCase = true)) {
                // Ubuntu Unity is a weird combination. It's "Gnome", but it's not "Gnome Shell".
                Env.Unity
            } else if ("unity:unity7".equals(XDG, ignoreCase = true)) {
                // Ubuntu Unity7 is a weird combination. It's "Gnome", but it's not "Gnome Shell".
                Env.Unity7
            } else if ("xfce".equals(XDG, ignoreCase = true)) {
                Env.XFCE
            } else if ("lxde".equals(XDG, ignoreCase = true)) {
                Env.LXDE
            } else if ("kde".equals(XDG, ignoreCase = true)) {
                Env.KDE
            } else if ("pantheon".equals(XDG, ignoreCase = true)) {
                Env.Pantheon
            } else if ("gnome".equals(XDG, ignoreCase = true)) {
                Env.Gnome
            } else if (isChromeOS) {
                // maybe it's chromeOS?
                Env.ChromeOS
            } else if (isMATE) {
                Env.MATE
            } else {
                Env.Unknown
            }
        }

        val isUnity = isUnity(env)

        fun isUnity(env: Env): Boolean {
            return env == Env.Unity || env == Env.Unity7
        }
    }
}
