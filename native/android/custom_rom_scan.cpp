#include "custom_rom_scan.h"
#include <sys/system_properties.h>
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

const char* kPolicyNote =
    " [custom-ROM/unlock is a policy WEIGHT, not malicious - GrapheneOS is more secure than stock]";

}

NativeResult check_crom_boot() {
    NativeResult r;
    std::string vbs = lower(prop("ro.boot.verifiedbootstate"));
    std::string flk = prop("ro.boot.flash.locked");
    std::string dev = lower(prop("ro.boot.vbmeta.device_state"));
    std::string ver = lower(prop("ro.boot.veritymode"));
    if (vbs.empty() && flk.empty() && dev.empty()) {
        r.status = STATUS_INCONCLUSIVE;
        r.details = "boot-state props unreadable - cannot judge";
        return r;
    }
    std::string hit;
    if (!vbs.empty() && vbs != "green") hit += "verifiedbootstate=" + vbs + " ";
    if (flk == "0") hit += "flash.locked=0 ";
    if (dev == "unlocked") hit += "device_state=unlocked ";
    if (!ver.empty() && ver != "enforcing") hit += "veritymode=" + ver + " ";
    if (!hit.empty()) {
        r.status = STATUS_DETECTED;
        r.details = "unlocked bootloader / non-green verified boot: " + hit + kPolicyNote;
    } else {
        r.status = STATUS_CLEAN; r.details = "locked bootloader, green verified boot, verity enforcing";
    }
    return r;
}

NativeResult check_crom_sign() {
    NativeResult r;
    std::string tags = lower(prop("ro.build.tags"));
    std::string type = lower(prop("ro.build.type"));
    std::string flavor = lower(prop("ro.build.flavor"));
    if (tags.empty() && type.empty()) {
        r.status = STATUS_INCONCLUSIVE; r.details = "build tags/type unreadable - cannot judge";
        return r;
    }
    std::string hit;
    if (has(tags, "test-keys")) hit += "tags=test-keys ";
    if (type == "userdebug" || type == "eng") hit += "type=" + type + " ";
    if (has(flavor, "userdebug") || has(flavor, "-eng")) hit += "flavor=" + flavor + " ";
    if (!hit.empty()) {
        r.status = STATUS_DETECTED;
        r.details = "non-release signing / debug build: " + hit + kPolicyNote;
    } else {
        r.status = STATUS_CLEAN; r.details = "release-keys tags and user build type";
    }
    return r;
}

NativeResult check_crom_rom_props() {
    NativeResult r;
    struct M { const char* key; const char* rom; };
    static const M kMarkers[] = {
        {"ro.lineage.version","LineageOS"}, {"ro.lineage.build.version","LineageOS"},
        {"ro.modversion","Lineage-family"}, {"ro.calyxos.version","CalyxOS"},
        {"ro.crdroid.version","crDroid"}, {"ro.evolution.version","EvolutionX"},
        {"ro.arrow.version","ArrowOS"}, {"ro.omni.version","OmniROM"},
        {"ro.rising.version","RisingOS"}, {"ro.leaf.version","LeafOS"},
        {"ro.nameless.version","Nameless"}, {"ro.yaap.version","YAAP"},
        {"ro.aospa.version","AOSPA"}, {"org.pixelexperience.version","PixelExperience"},
        {"org.elixir.version","ProjectElixir"}, {"ro.elegal.url","/e/OS"},
        {"ro.pixelos.version","PixelOS"}, {nullptr,nullptr}
    };
    std::string hit;
    for (int i = 0; kMarkers[i].key; ++i) {
        std::string v = prop(kMarkers[i].key);
        if (!v.empty()) hit += std::string(kMarkers[i].rom) + "(" + kMarkers[i].key + ") ";
    }
    if (!hit.empty()) {
        r.status = STATUS_DETECTED; r.details = "custom-ROM marker prop(s): " + hit + kPolicyNote;
    } else {
        r.status = STATUS_CLEAN; r.details = "no custom-ROM version marker property";
    }
    return r;
}
