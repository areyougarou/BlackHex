#include "emulator_hw.h"
#include <android/sensor.h>
#include <vulkan/vulkan.h>
#include <cctype>
#include <string>
#include <vector>

namespace {
std::string lower(std::string s) { for (char& c : s) c = (char)tolower((unsigned char)c); return s; }
}

static NativeResult vulkan_probe() {
    NativeResult r;

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    if (vkCreateInstance(&ci, nullptr, &inst) != VK_SUCCESS || inst == VK_NULL_HANDLE) {
        r.status = STATUS_INCONCLUSIVE;
        r.details = "vkCreateInstance failed - no Vulkan loader/driver; cannot judge";
        return r;
    }

    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    if (count == 0) {
        vkDestroyInstance(inst, nullptr);
        r.status = STATUS_INCONCLUSIVE;
        r.details = "no Vulkan physical devices - cannot judge";
        return r;
    }
    std::vector<VkPhysicalDevice> devs(count);
    vkEnumeratePhysicalDevices(inst, &count, devs.data());

    std::string detail, raw;
    bool software = false, hardware = false;
    for (auto d : devs) {
        VkPhysicalDeviceProperties p{};
        vkGetPhysicalDeviceProperties(d, &p);
        std::string name = lower(p.deviceName);
        raw += std::string(p.deviceName) + "(type=" + std::to_string((int)p.deviceType) + ") ";
        if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU ||
            name.find("swiftshader") != std::string::npos || name.find("llvmpipe") != std::string::npos ||
            name.find("lavapipe") != std::string::npos || name.find("virgl") != std::string::npos ||
            name.find("softpipe") != std::string::npos) {
            software = true; detail += "  software renderer: " + std::string(p.deviceName) + "\n";
        } else if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ||
                   p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            hardware = true;
        }
    }
    vkDestroyInstance(inst, nullptr);
    if (software) { r.status = STATUS_DETECTED; r.details = "Vulkan reports a software GPU (emulator):\n" + detail; }
    else if (hardware) { r.status = STATUS_CLEAN; r.details = "hardware Vulkan GPU: " + raw; }
    else { r.status = STATUS_INCONCLUSIVE; r.details = "Vulkan device type not conclusive: " + raw; }
    return r;
}

static NativeResult sensors_probe() {
    NativeResult r;

    ASensorManager* m = nullptr;
    const char* pkg = g_own_process_name.empty() ? "rasp.sdk" : g_own_process_name.c_str();
#if __ANDROID_API__ >= 26
    m = ASensorManager_getInstanceForPackage(pkg);
#else
    m = ASensorManager_getInstance();
#endif
    if (!m) { r.status = STATUS_INCONCLUSIVE; r.details = "sensor manager unavailable - cannot judge"; return r; }

    ASensorList list = nullptr;
    int n = ASensorManager_getSensorList(m, &list);
    std::string vendors, emu_hit;
    static const char* kEmuVendors[] = {"genymobile","genymotion","goldfish","ranchu",
        "vbox","bluestacks","android emulator","nox", nullptr};
    for (int i = 0; i < n && list; ++i) {
        const char* v = ASensor_getVendor(list[i]);
        std::string lv = lower(v ? v : "");
        if (i < 12) vendors += std::string(v ? v : "?") + "; ";
        for (int k = 0; kEmuVendors[k]; ++k)
            if (!lv.empty() && lv.find(kEmuVendors[k]) != std::string::npos) { emu_hit += lv + " "; break; }
    }
    std::string raw = "sensor_count=" + std::to_string(n) + " emu_vendor=[" + emu_hit + "] vendors=[" + vendors + "]";
    if (!emu_hit.empty()) { r.status = STATUS_DETECTED; r.details = "emulator sensor vendor present: " + raw; }
    else if (n <= 0) { r.status = STATUS_INCONCLUSIVE; r.details = "no sensors to read vendors from - cannot judge: " + raw; }
    else { r.status = STATUS_CLEAN; r.details = "no emulator sensor vendor: " + raw; }
    return r;
}

NativeResult check_emu_vulkan() {
    static const NativeResult once = vulkan_probe();
    return once;
}

NativeResult check_emu_sensors() {
    static const NativeResult once = sensors_probe();
    return once;
}
