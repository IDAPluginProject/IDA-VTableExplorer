#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

struct VTableInfo {
    ea_t address;
    std::string class_name;
    std::string display_name;
    bool is_windows;
};

namespace vtable_detector {

// Demangle and extract class name from symbol
inline std::string extract_class_name(const char* mangled_name, bool& is_windows) {
    std::string sym_name(mangled_name);
    qstring demangled;
    is_windows = false;

    if (sym_name.length() > 4 && sym_name.substr(sym_name.length() - 4) == "_ptr")
        sym_name = sym_name.substr(0, sym_name.length() - 4);

    int demangle_result = demangle_name(&demangled, sym_name.c_str(), MNG_NODEFINIT);

    if (demangle_result > 0) {
        std::string dem_str(demangled.c_str());

        if (dem_str.find("vtable for") != std::string::npos) {
            size_t pos = dem_str.find("vtable for ");
            if (pos != std::string::npos) {
                std::string class_name = dem_str.substr(pos + 11);
                return class_name;
            }
        }

        if (dem_str.find("vftable") != std::string::npos) {
            is_windows = true;
            size_t const_pos = dem_str.find("const ");
            size_t vft_pos = dem_str.find("::`vftable'");

            if (const_pos != std::string::npos && vft_pos != std::string::npos) {
                size_t start = const_pos + 6;
                std::string class_name = dem_str.substr(start, vft_pos - start);
                return class_name;
            }
        }
    }

    // Fallback: parse Itanium mangling manually
    if (sym_name.rfind("_ZTV", 0) == 0) {
        const char* name_start = sym_name.c_str() + 4;

        if (name_start[0] == 'N') {
            const char* p = name_start + 1;
            std::string last_component;

            while (*p && *p != 'E') {
                if (isdigit(*p)) {
                    int len = atoi(p);
                    while (isdigit(*p)) p++;

                    if (len > 0 && len < 1024) {
                        last_component = std::string(p, len);
                        p += len;
                    }
                } else {
                    p++;
                }
            }

            if (!last_component.empty())
                return last_component;
        }
        else if (isdigit(name_start[0])) {
            int name_len = atoi(name_start);
            const char* name_ptr = name_start;
            while (isdigit(*name_ptr)) name_ptr++;

            if (name_len > 0 && name_len < 1024) {
                std::string class_name(name_ptr, name_len);
                return class_name;
            }
        }
    }

    return "";
}

// Symbol-based vtable detection (like Python version)
inline std::vector<VTableInfo> find_vtables() {
    std::vector<VTableInfo> vtables;
    std::map<std::string, ea_t> seen;

    msg("[VTableExplorer] Scanning symbols...\n");

    size_t name_count = get_nlist_size();

    for (size_t i = 0; i < name_count; ++i) {
        ea_t ea = get_nlist_ea(i);
        const char* name = get_nlist_name(i);

        if (!name || name[0] == '\0')
            continue;

        std::string sym_name(name);
        bool is_windows = false;
        std::string class_name;

        // Linux/GCC vtables: _ZTV prefix
        if (sym_name.rfind("_ZTV", 0) == 0) {
            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (!class_name.empty()) {
                VTableInfo info;
                info.address = ea;
                info.class_name = class_name;
                info.display_name = class_name + " (Linux/GCC)";
                info.is_windows = false;

                if (seen.find(info.display_name) == seen.end()) {
                    seen[info.display_name] = ea;
                    vtables.push_back(info);
                }
            }
        }
        // Windows/MSVC vtables: ??_7 prefix
        else if (sym_name.rfind("??_7", 0) == 0) {
            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (class_name.empty() && sym_name.find("@@6B@") != std::string::npos) {
                class_name = sym_name.substr(4, sym_name.find("@@6B@") - 4);
            }

            if (!class_name.empty()) {
                VTableInfo info;
                info.address = ea;
                info.class_name = class_name;
                info.display_name = class_name + " (Windows/MSVC)";
                info.is_windows = true;

                if (seen.find(info.display_name) == seen.end()) {
                    seen[info.display_name] = ea;
                    vtables.push_back(info);
                }
            }
        }
        // Additional patterns: vftable, vtbl in name
        else if (sym_name.find("vftable") != std::string::npos ||
                 sym_name.find("vtbl") != std::string::npos) {

            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (class_name.empty()) {
                class_name = sym_name;
                is_windows = true;
            }

            VTableInfo info;
            info.address = ea;
            info.class_name = class_name;
            info.display_name = class_name + " (Detected)";
            info.is_windows = is_windows;

            if (seen.find(info.display_name) == seen.end()) {
                seen[info.display_name] = ea;
                vtables.push_back(info);
            }
        }
    }

    // Sort by class name
    std::sort(vtables.begin(), vtables.end(),
        [](const VTableInfo& a, const VTableInfo& b) {
            return a.display_name < b.display_name;
        });

    msg("[VTableExplorer] Total vtables found: %d\n", (int)vtables.size());
    return vtables;
}

} // namespace vtable_detector
