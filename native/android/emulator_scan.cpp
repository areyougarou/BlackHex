#include "emulator_scan.h"
#include <sys/system_properties.h>
#include <sys/stat.h>
#include <cctype>
#include <string>

namespace {

std::string prop(const char* key) {
    char v[PROP_VALUE_MAX] = {};
    int n = __system_property_get(key, v);
    return n > 0 ? std::string(v, (size_t)n) : std::string();
}

std::string lower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

bool has(const std::string& hay_lc, const char* needle_lc) {
    return hay_lc.find(needle_lc) != std::string::npos;
}

bool exists(const char* p) { struct stat st{}; return stat(p, &st) == 0; }

}

NativeResult check_emu_cpu_isa() {
    NativeResult r;
    std::string ci = read_proc_file("/proc/cpuinfo");
    if (ci.empty()) { r.status = STATUS_INCONCLUSIVE; r.details = "cpuinfo unreadable - cannot judge"; return r; }
    std::string lc = lower(ci);
    std::string hit;
    for (const char* s : {"model name", "vendor_id", "genuineintel", "authenticamd",
                          " vmx ", " svm ", "hypervisor"})
        if (has(lc, s)) hit += std::string(s) + " ";
    for (const char* s : {"goldfish", "ranchu", "vbox", "android emulator"})
        if (has(lc, s)) hit += std::string(s) + " ";
    if (!hit.empty()) { r.status = STATUS_DETECTED; r.details = "x86/virtualization/emulator markers: " + hit; }
    else { r.status = STATUS_CLEAN; r.details = "arm64 CPU, no x86/hypervisor/emulator markers"; }
    return r;
}

NativeResult check_emu_translator() {
    NativeResult r;
    static const char* kLibs[] = {"libhoudini", "libndk_translation", "libnb.so",
                                   "libdvm_houdini", "/houdini", "libnativebridge_vdex", nullptr};
    std::string hit;
    for (const auto& v : g_maps) {
        std::string p = lower(v.path);
        for (int i = 0; kLibs[i]; ++i)
            if (p.find(kLibs[i]) != std::string::npos) { hit += v.path + " "; break; }
    }
    if (!hit.empty()) { r.status = STATUS_DETECTED; r.details = "ARM translator mapped: " + hit; }
    else { r.status = STATUS_CLEAN; r.details = "no ARM-translation library in own maps"; }
    return r;
}

NativeResult check_emu_props_qemu() {
    std::string qemu = prop("ro.boot.qemu") + prop("ro.kernel.qemu");
    std::string hw = lower(prop("ro.hardware"));
    std::string egl = lower(prop("ro.hardware.egl")), gralloc = lower(prop("ro.hardware.gralloc"));
    std::string hit;
    if (qemu.find('1') != std::string::npos) hit += "qemu=1 ";
    if (hw == "goldfish" || hw == "ranchu" || hw == "vbox86") hit += "hardware=" + hw + " ";
    if (egl.find("emulation") != std::string::npos || egl.find("ranchu") != std::string::npos ||
        gralloc.find("ranchu") != std::string::npos || gralloc.find("emulation") != std::string::npos)
        hit += "egl/gralloc=emulated ";
    std::string raw = "qemu=[" + qemu + "] hw=" + hw + " egl=" + egl + " gralloc=" + gralloc;
    if (!hit.empty()) return {STATUS_DETECTED, "emulator props: " + hit + "\n" + raw};
    return {STATUS_CLEAN, "no qemu/goldfish/ranchu/vbox86/emulated-EGL props\n" + raw};
}

NativeResult check_emu_props_hints() {
    std::string hw = lower(prop("ro.hardware"));
    std::string abi = lower(prop("ro.product.cpu.abi"));
    std::string bridge = prop("ro.dalvik.vm.native.bridge");
    std::string hit;
    if (hw != "goldfish" && hw != "ranchu" && hw != "vbox86")
        for (const char* h : {"goldfish","ranchu","vbox86","nox","ttvm","android_x86","cancro"})
            if (hw.find(h) != std::string::npos) { hit += "hardware=" + hw + " "; break; }
    if (abi.find("x86") != std::string::npos) hit += "abi=" + abi + " ";
    if (!bridge.empty() && bridge != "0" && lower(bridge).find("false") == std::string::npos)
        hit += "native_bridge=" + bridge + " ";
    std::string raw = "hw=" + hw + " abi=" + abi + " bridge=" + bridge;
    if (!hit.empty()) return {STATUS_DETECTED, "emulator-like props: " + hit + "\n" + raw};
    return {STATUS_CLEAN, "no emulator-like hardware name, x86 ABI or native bridge\n" + raw};
}

NativeResult check_emu_devnodes() {
    NativeResult r;
    static const char* kNodes[] = {"/dev/qemu_pipe","/dev/goldfish_pipe","/dev/goldfish_sync",
        "/dev/socket/qemud","/dev/socket/baseband_genyd","/dev/socket/genyd",
        "/dev/vboxguest","/dev/vboxuser", nullptr};
    std::string hit;
    for (int i = 0; kNodes[i]; ++i) if (exists(kNodes[i])) hit += std::string(kNodes[i]) + " ";
    std::string tty = lower(read_proc_file("/proc/tty/drivers"));
    if (has(tty, "goldfish")) hit += "tty:goldfish ";
    if (!hit.empty()) { r.status = STATUS_DETECTED; r.details = "emulator device nodes present: " + hit; }
    else { r.status = STATUS_CLEAN; r.details = "no qemu/goldfish/vbox device nodes"; }
    return r;
}

NativeResult check_emu_mounts() {
    NativeResult r;
    std::string mi = lower(read_proc_file("/proc/self/mountinfo"));
    if (mi.empty()) { r.status = STATUS_INCONCLUSIVE; r.details = "mountinfo unreadable - cannot judge"; return r; }
    std::string hit;
    for (const char* s : {" vboxsf", " 9p ", "virtiofs", " virtio"})
        if (has(mi, s)) hit += std::string(s) + " ";
    if (!hit.empty()) { r.status = STATUS_DETECTED; r.details = "paravirtual filesystem mounts: " + hit; }
    else { r.status = STATUS_CLEAN; r.details = "no 9p/vboxsf/virtiofs mounts"; }
    return r;
}
