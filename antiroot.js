const ROOT_CHECK_FULL_PATH = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/sbin/supersu",
    "/sbin/magisk",
    "/sbin/magiskhide",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/sbin/supersu",
    "/system/sbin/magisk",
    "/system/sbin/busybox",
    "/system/sbin/magiskhide",
    "/sbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/product/bin/su",
    "/product/bin/magisk",
    "/product/bin/busybox",
];
const ROOT_CHECK_FILE_SUFFIX = [
   // "/maps",
   // "/status"
];
const ROOT_CHECK_DIR_SUFFIX = [
   // "/fd",
   // "/task"
];
const ROOT_CHECK_SU_CMD = [
    "su",
    "supersu",
    "busybox",
    "magisk",
    "magiskhide",
    "daemonsu",
    "Kinguser.apk",
    "Superuser.apk"
];

const ROOT_CHECK_MANAGEMENT_APP = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "me.phh.superuser",
    "eu.chainfire.supersu.pro",
    "com.kingouser.com",
    "com.topjohnwu.magisk"
];

// print java stack trace
function printStackTrace() {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackInfo = Log.getStackTraceString(Exception.$new());
    console.log(stackInfo);
}

// print native stack trace
function printStackTraceNative(){
    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join("\n");
    console.log(backtrace)
}

// fgets: read line
// todo: get file name by fp and check it's /proc/xxx/status file to improve performance
function handleTracePidCheck() {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufStr = Memory.readUtf8String(buffer);
        if (bufStr.indexOf("TracerPid:") > -1) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
            console.log("fake result for tracepid: " + Memory.readUtf8String(buffer));
        }
        return retval;
    }, "pointer", ["pointer", "int", "pointer"]));
};

function handleWithJavaFileCheck() {
    var File = Java.use("java.io.File");
    var UnixFileSystem = Java.use("java.io.UnixFileSystem");
    // handle file.exists
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        console.log("java file exists method called for: " + path);
        if (ROOT_CHECK_FULL_PATH.indexOf(path) >= 0) {
            console.log("fake result for file exists: " + path);
            return false;
        }
        return this.exists();
    }
    // handle file real implementation for ops
    UnixFileSystem.checkAccess.implementation = function(file, access){
        const filePath = file.getAbsolutePath();
        console.log("unix file system access called for: " + filePath);
        var fields = filePath.split("/");
        var exec = fields[fields.length - 1];
        if (ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
            console.log("fake result for checkAccess: " + filePath);
            return false;
        }
        if (ROOT_CHECK_FULL_PATH.indexOf(filePath) >= 0) {
            console.log("fake result for checkAccess: " + filePath)
            return false;
        }
        for (let i = 0; i < ROOT_CHECK_FILE_SUFFIX.length; i++) {
            if (filePath.endsWith(ROOT_CHECK_FILE_SUFFIX[i])) {
                console.log("fake result for checkAccess: " + filePath);
                return false;
            }
        }
        for (let i = 0; i < ROOT_CHECK_DIR_SUFFIX.length; i++) {
            if (filePath.endsWith(ROOT_CHECK_DIR_SUFFIX[i])) {
                console.log("fake result for checkAccess: " + filePath);
                return false;
            }
        }
        return this.checkAccess(file, access);
    }
}

function handleWithNativeFileCheck() {
    var access = Module.findExportByName("libc.so", "access");
    var faccessat = Module.findExportByName("libc.so", "faccessat");
    var open = Module.findExportByName("libc.so", "open");
    var openat = Module.findExportByName("libc.so", "openat");
    var stat = Module.findExportByName("libc.so", "stat");
    var lstat = Module.findExportByName("libc.so", "lstat");
    var fstatat = Module.findExportByName("libc.so", "fstatat");
    var ls = Module.findExportByName("libc.so", "fstatat");
    var opendir = Module.findExportByName("libc.so", "opendir");

    Interceptor.attach(opendir, {
        onEnter: function(args) {
            this.inputPath = args[0].readUtf8String();
            console.log("opendir called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if (retval.toInt32() != 0) {
                var fields = this.inputPath.split("/");
                var suffix = "/" + fields[fields.length - 1];
                if (ROOT_CHECK_DIR_SUFFIX.indexOf(suffix) >= 0) {
                    console.log("fake result for opendir: " + this.inputPath);
                    retval.replace(ptr(0x0));
                }
            }
        }
    });

    Interceptor.attach(stat, {
        onEnter: function(args) {
            this.inputPath = args[0].readUtf8String();
            console.log("stat called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() == 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for stat: " + this.inputPath);
                    retval.replace(-1);
                }
            }
        }
    });

    Interceptor.attach(lstat, {
        onEnter: function(args) {
            this.inputPath = args[0].readUtf8String();
            console.log("lstat called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() == 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for lstat: " + this.inputPath);
                    retval.replace(-1);
                }
            }
        }
    });

    Interceptor.attach(fstatat, {
        onEnter: function(args) {
            this.inputPath = args[1].readUtf8String();
            console.log("fstatat called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() == 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for fstatat: " + this.inputPath);
                    retval.replace(-1);
                }
            }
        }
    });

    Interceptor.attach(open, {
        onEnter: function(args) {
            this.inputPath = args[0].readUtf8String();
            console.log("open called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() != 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for open: " + this.inputPath);
                    retval.replace(-1);
                }
                for (let i = 0; i < ROOT_CHECK_FILE_SUFFIX.length; i++) {
                    if (this.inputPath.endsWith(ROOT_CHECK_FILE_SUFFIX[i])) {
                        console.log("fake result for open: " + this.inputPath);
                        retval.replace(-1);
                    }
                }
            }
        }
    });

    Interceptor.attach(openat, {
        onEnter: function(args) {
            this.inputPath = args[0].readUtf8String();
            console.log("openat called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() != 0){
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for openat: " + this.inputPath)
                    retval.replace(-1);
                }
            }
        }
    });

    Interceptor.attach(faccessat, {
        onEnter: function(args) {
            this.inputPath = args[1].readUtf8String();
            console.log("faccessat called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() == 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if (ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0) {
                    console.log("fake result for faccessat: " + this.inputPath);
                    retval.replace(-1);
                }
            }
        }
    });

    Interceptor.attach(access, {
        onEnter:function(args){
            this.inputPath = args[0].readUtf8String();
            console.log("access called: " + this.inputPath);
        },
        onLeave: function(retval) {
            if(retval.toInt32() == 0) {
                var fields = this.inputPath.split("/");
                var exec = fields[fields.length - 1];
                if(ROOT_CHECK_FULL_PATH.indexOf(this.inputPath) >= 0 || ROOT_CHECK_SU_CMD.indexOf(exec) >= 0){
                    console.log("fake result for access: " + this.inputPath);
                    retval.replace(-1);
                }
            }
        }
    });
}

// android.app.PackageManager
function handleWithRootAppCheck(){
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
    ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i){
        console.log("android application manager getPackageInfo: " + str);
        if (ROOT_CHECK_MANAGEMENT_APP.indexOf(str) >= 0) {
            console.log("fake result for getPackageInfo: " + str);
            str = "com.fake.fake.package";
        }
        return this.getPackageInfo(str, i);
    }
}

function handleWithShellCheck() {
    var String = Java.use('java.lang.String')
    var ProcessImpl = Java.use("java.lang.ProcessImpl")
    ProcessImpl.start.implementation = function(cmdArray, env, dir, redirects, redirectErrorStream){
        var cmdline = cmdArray.toString();
        console.log("java ProcessImpl: " + cmdline);
        if (cmdline.endsWith("/su")) {
            console.log("fake result for process run: " + cmdline);
            arguments[0] = Java.array('java.lang.String',[String.$new("")])
            return ProcessImpl.start.apply(this, arguments);
        }
        if(cmdArray[0] == "mount"){
            console.log("fake result for process mount: " + cmdline);
            arguments[0] = Java.array('java.lang.String',[String.$new("")]);
            return ProcessImpl.start.apply(this, arguments);
        }
        // getprop ro.secure
        if(cmdArray[0] == "getprop"){
            const prop = [
                "ro.secure",
                "ro.debuggable"
            ];
            if(prop.indexOf(cmdArray[1]) >= 0) {
                console.log("fake result for process getprop: " + cmdline);
                arguments[0] = Java.array('java.lang.String', [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }
        }
        // which su
        if(cmdArray[0].indexOf("which") >= 0){
            const prop = [
                "su"
            ];
            if(prop.indexOf(cmdArray[1]) >= 0) {
                console.log("fake result for which: " + cmdline);
                arguments[0] = Java.array('java.lang.String', [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments)
            }
        }
        return ProcessImpl.start.apply(this,arguments);
    }
}

function fakeProp(){
    var Build = Java.use("android.os.Build")
    var Tags = Build.class.getDeclaredField("TAGS")
    Tags.setAccessible(true);
    Tags.set(null, "release-keys");
    var fingerprint = Build.class.getDeclaredField("FINGERPRINT")
    fingerprint.setAccessible(true)
    fingerprint.set(null, "OnePlus/OnePlus6T/OnePlus6T:9/PKQ1.180716.001/1812111152:user/release-keys");
    var system_property_get = Module.findExportByName("libc.so", "__system_property_get")
    Interceptor.attach(system_property_get, {
        onEnter(args) {
            this.key = args[0].readCString();
            this.ret = args[1];
        },
        onLeave(ret) {
            if(this.key == "ro.build.fingerprint") {
                var tmp = "OnePlus/OnePlus6T/OnePlus6T:9/PKQ1.180716.001/1812111152:user/release-keys";
                var p = Memory.allocUtf8String(tmp);
                Memory.copy(this.ret, p, tmp.length + 1);
            }
        }
    });
}

fakeProp();
handleTracePidCheck();
handleWithJavaFileCheck();
handleWithNativeFileCheck();
handleWithRootAppCheck();
handleWithShellCheck();


