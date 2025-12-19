#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <segment.hpp>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include "vtable_utils.h"

namespace rtti_parser {

using vtable_utils::get_ptr_size;
using vtable_utils::read_ptr;
using vtable_utils::read_int32;

struct BaseClassInfo {
    std::string class_name;
    ea_t vtable_addr;
    int offset;
    bool is_virtual;
};

struct InheritanceInfo {
    std::string class_name;
    std::vector<BaseClassInfo> base_classes;
    bool has_multiple_inheritance;
    bool has_virtual_inheritance;
};

namespace gcc_rtti {

inline std::string read_string(ea_t addr) {
    if (!is_mapped(addr)) return "";

    std::string result;
    result.reserve(128);

    for (int i = 0; i < vtable_utils::MAX_RTTI_STRING_LENGTH; ++i) {
        char c = get_byte(addr + i);
        if (c == 0) break;
        if (!isprint(c) && c != '_') break;
        result.push_back(c);
    }

    return result;
}

inline std::string extract_class_name_from_mangled(const std::string& mangled) {
    if (mangled.empty()) return "";

    // Handle GCC _ZTS format: _ZTS{length}{name}
    // Example: _ZTS5CBeam → "CBeam"
    if (mangled.compare(0, 4, "_ZTS") == 0 && mangled.length() > 4) {
        const char* p = mangled.c_str() + 4;
        if (isdigit(*p)) {
            int len = atoi(p);
            while (isdigit(*p)) ++p;

            if (len > 0 && len < 256 && strlen(p) >= (size_t)len) {
                return std::string(p, len);
            }
        }
    }

    // Handle direct {length}{name} format (without _ZTS prefix)
    // Example: "5CBeam" → "CBeam"
    if (isdigit(mangled[0])) {
        const char* p = mangled.c_str();
        int len = atoi(p);
        while (isdigit(*p)) ++p;

        if (len > 0 && len < 256 && strlen(p) >= (size_t)len) {
            return std::string(p, len);
        }
    }

    // Try full demangling as fallback
    qstring demangled;
    if (demangle_name(&demangled, mangled.c_str(), MNG_NODEFINIT) > 0) {
        std::string dem_str = demangled.c_str();

        // Remove "typeinfo for " prefix if present
        const char* prefix = "typeinfo for ";
        size_t pos = dem_str.find(prefix);
        if (pos != std::string::npos) {
            return dem_str.substr(pos + strlen(prefix));
        }

        return dem_str;
    }

    return "";
}

inline InheritanceInfo parse_gcc_typeinfo(ea_t typeinfo_addr, const std::string& derived_class) {
    InheritanceInfo info;
    info.class_name = derived_class;
    info.has_multiple_inheritance = false;
    info.has_virtual_inheritance = false;

    if (!is_mapped(typeinfo_addr)) return info;

    // GCC typeinfo structure:
    // +0: vtable pointer (points to typeinfo's vtable)
    // +ptr_size: name pointer (mangled name string)

    const int ptr_size = get_ptr_size();
    ea_t vtable_ptr = read_ptr(typeinfo_addr);
    ea_t name_ptr = read_ptr(typeinfo_addr + ptr_size);

    if (vtable_ptr == BADADDR || name_ptr == BADADDR) {
        std::string direct_name = read_string(typeinfo_addr + ptr_size);
        if (!direct_name.empty() && direct_name.find("_ZTS") == 0) {
            return info;
        }
        return info;
    }

    qstring typeinfo_vtable_name;
    bool got_name = get_name(&typeinfo_vtable_name, vtable_ptr);

    if (got_name && typeinfo_vtable_name.find("off_") == 0) {
        got_name = false;
    }

    if (!got_name) {
        ea_t indirect_vtable = read_ptr(vtable_ptr);

        if (indirect_vtable != BADADDR && is_mapped(indirect_vtable)) {
            if (get_name(&typeinfo_vtable_name, indirect_vtable)) {
                vtable_ptr = indirect_vtable;
            }
        }

        if (typeinfo_vtable_name.empty()) {
            ea_t base_typeinfo = read_ptr(typeinfo_addr + 2 * ptr_size);

            if (base_typeinfo != BADADDR && is_mapped(base_typeinfo)) {
                ea_t base_name_ptr = read_ptr(base_typeinfo + ptr_size);

                if (base_name_ptr != BADADDR) {
                    std::string base_mangled = read_string(base_name_ptr);
                    std::string base_class = extract_class_name_from_mangled(base_mangled);

                    if (!base_class.empty()) {
                        BaseClassInfo base;
                        base.class_name = base_class;
                        base.vtable_addr = BADADDR;
                        base.offset = 0;
                        base.is_virtual = false;
                        info.base_classes.push_back(base);
                    }
                }
            }
            return info;
        }
    }

    const char* vt_name = typeinfo_vtable_name.c_str();

    // __si_class_type_info: single inheritance
    if (strstr(vt_name, "__si_class_type_info")) {
        // +2*ptr_size: pointer to base class typeinfo
        ea_t base_typeinfo = read_ptr(typeinfo_addr + 2 * ptr_size);

        if (base_typeinfo != BADADDR) {
            ea_t base_name_ptr = read_ptr(base_typeinfo + ptr_size);

            if (base_name_ptr != BADADDR) {
                std::string base_mangled = read_string(base_name_ptr);
                std::string base_class = extract_class_name_from_mangled(base_mangled);

                if (!base_class.empty()) {
                    BaseClassInfo base;
                    base.class_name = base_class;
                    base.vtable_addr = BADADDR; // Will be resolved later
                    base.offset = 0;
                    base.is_virtual = false;
                    info.base_classes.push_back(base);
                }
            }
        }
    }
    // __vmi_class_type_info: multiple/virtual inheritance
    else if (strstr(vt_name, "__vmi_class_type_info")) {
        info.has_multiple_inheritance = true;

        // +2*ptr_size: flags
        // +3*ptr_size: base_count
        // +4*ptr_size: first base_class_type_info

        int32 flags = read_int32(typeinfo_addr + 2 * ptr_size);
        int32 base_count = read_int32(typeinfo_addr + 3 * ptr_size);

        if (flags & 1) { // __non_diamond_repeat_mask
            info.has_virtual_inheritance = true;
        }

        if (base_count > 0 && base_count < 32) {
            ea_t base_info_array = typeinfo_addr + 4 * ptr_size;

            for (int i = 0; i < base_count; ++i) {
                ea_t base_entry = base_info_array + (i * 2 * ptr_size);
                ea_t base_typeinfo = read_ptr(base_entry);
                int32 offset_flags = read_int32(base_entry + ptr_size);

                if (base_typeinfo != BADADDR) {
                    ea_t base_name_ptr = read_ptr(base_typeinfo + ptr_size);
                    if (base_name_ptr != BADADDR) {
                        std::string base_mangled = read_string(base_name_ptr);
                        std::string base_class = extract_class_name_from_mangled(base_mangled);

                        if (!base_class.empty()) {
                            BaseClassInfo base;
                            base.class_name = base_class;
                            base.vtable_addr = BADADDR;
                            base.offset = (offset_flags >> 8); // offset is in high bits
                            base.is_virtual = (offset_flags & 1) != 0; // virtual flag in low bit
                            info.base_classes.push_back(base);
                        }
                    }
                }
            }
        }
    }

    return info;
}

} // namespace gcc_rtti

// MSVC/Windows RTTI structures
namespace msvc_rtti {

// MSVC RTTI structures (32-bit and 64-bit compatible)
struct RTTICompleteObjectLocator {
    uint32 signature;
    uint32 offset;
    uint32 cdOffset;
    int32 pTypeDescriptor;  // RVA in 64-bit, pointer in 32-bit
    int32 pClassDescriptor; // RVA in 64-bit, pointer in 32-bit
    // 64-bit has additional field: int32 pSelf
};

inline ea_t rva_to_va(ea_t image_base, int32 rva) {
    if (rva == 0) return BADADDR;
    return image_base + rva;
}

inline ea_t find_image_base(ea_t addr) {
    segment_t* seg = getseg(addr);
    if (!seg) return BADADDR;

    // Find the first segment (usually the image base)
    segment_t* first_seg = get_first_seg();
    if (!first_seg) return BADADDR;

    return first_seg->start_ea;
}

inline std::string read_msvc_type_name(ea_t type_descriptor_addr) {
    if (!is_mapped(type_descriptor_addr)) return "";

    const int ptr_size = get_ptr_size();

    // TypeDescriptor structure:
    // +0: vtable pointer
    // +ptr_size: spare pointer
    // +2*ptr_size: name (null-terminated string)

    ea_t name_addr = type_descriptor_addr + 2 * ptr_size;

    std::string result;
    result.reserve(128);

    for (int i = 0; i < vtable_utils::MAX_RTTI_STRING_LENGTH; ++i) {
        char c = get_byte(name_addr + i);
        if (c == 0) break;
        if (!isprint(c) && c != '_') break;
        result.push_back(c);
    }

    // MSVC mangled names start with .?AV for classes
    if (result.length() > 4 && result.substr(0, 4) == ".?AV") {
        result = result.substr(4);
        // Remove trailing @@ if present
        size_t at_pos = result.find("@@");
        if (at_pos != std::string::npos) {
            result = result.substr(0, at_pos);
        }
    }

    return result;
}

inline InheritanceInfo parse_msvc_col(ea_t col_addr, const std::string& derived_class) {
    InheritanceInfo info;
    info.class_name = derived_class;
    info.has_multiple_inheritance = false;
    info.has_virtual_inheritance = false;

    if (!is_mapped(col_addr)) return info;

    const int ptr_size = get_ptr_size();
    const bool is_64bit = (ptr_size == 8);

    // Read COL structure
    uint32 signature = get_dword(col_addr);
    uint32 offset = get_dword(col_addr + 4);
    uint32 cdOffset = get_dword(col_addr + 8);
    int32 type_desc_rva = get_dword(col_addr + 12);
    int32 class_desc_rva = get_dword(col_addr + 16);

    // Validate signature (should be 0 for 32-bit, 1 for 64-bit)
    if ((is_64bit && signature != 1) || (!is_64bit && signature != 0)) {
        return info;
    }

    ea_t image_base = BADADDR;
    ea_t type_desc_addr = BADADDR;
    ea_t class_desc_addr = BADADDR;

    if (is_64bit) {
        // 64-bit uses RVAs
        image_base = find_image_base(col_addr);
        if (image_base == BADADDR) return info;

        type_desc_addr = rva_to_va(image_base, type_desc_rva);
        class_desc_addr = rva_to_va(image_base, class_desc_rva);
    } else {
        // 32-bit uses direct pointers
        type_desc_addr = type_desc_rva;
        class_desc_addr = class_desc_rva;
    }

    if (type_desc_addr == BADADDR || class_desc_addr == BADADDR) return info;

    // ClassHierarchyDescriptor structure:
    // +0: signature (0)
    // +4: attributes (bit 0: multiple inheritance, bit 1: virtual inheritance)
    // +8: numBaseClasses
    // +12: pBaseClassArray (RVA in 64-bit, pointer in 32-bit)

    uint32 chd_signature = get_dword(class_desc_addr);
    uint32 attributes = get_dword(class_desc_addr + 4);
    uint32 num_base_classes = get_dword(class_desc_addr + 8);
    int32 base_array_rva = get_dword(class_desc_addr + 12);

    info.has_multiple_inheritance = (attributes & 1) != 0;
    info.has_virtual_inheritance = (attributes & 2) != 0;

    if (num_base_classes == 0 || num_base_classes > 64) return info;

    ea_t base_array_addr;
    if (is_64bit) {
        base_array_addr = rva_to_va(image_base, base_array_rva);
    } else {
        base_array_addr = base_array_rva;
    }

    if (base_array_addr == BADADDR) return info;

    // BaseClassDescriptor array (array of pointers/RVAs)
    for (uint32 i = 0; i < num_base_classes; ++i) {
        ea_t bcd_ptr_addr = base_array_addr + (i * 4); // Always 4 bytes (RVA or pointer)
        int32 bcd_rva = get_dword(bcd_ptr_addr);

        ea_t bcd_addr;
        if (is_64bit) {
            bcd_addr = rva_to_va(image_base, bcd_rva);
        } else {
            bcd_addr = bcd_rva;
        }

        if (bcd_addr == BADADDR) continue;

        // BaseClassDescriptor structure:
        // +0: pTypeDescriptor (RVA/pointer)
        // +4: numContainedBases
        // +8: PMD where (mdisp, pdisp, vdisp)
        // +20: attributes

        int32 base_type_desc_rva = get_dword(bcd_addr);
        uint32 num_contained = get_dword(bcd_addr + 4);
        int32 mdisp = get_dword(bcd_addr + 8);
        int32 pdisp = get_dword(bcd_addr + 12);
        int32 vdisp = get_dword(bcd_addr + 16);
        uint32 bcd_attributes = get_dword(bcd_addr + 20);

        ea_t base_type_desc_addr;
        if (is_64bit) {
            base_type_desc_addr = rva_to_va(image_base, base_type_desc_rva);
        } else {
            base_type_desc_addr = base_type_desc_rva;
        }

        if (base_type_desc_addr == BADADDR) continue;

        std::string base_class = read_msvc_type_name(base_type_desc_addr);

        if (!base_class.empty() && base_class != derived_class) {
            BaseClassInfo base;
            base.class_name = base_class;
            base.vtable_addr = BADADDR;
            base.offset = mdisp;
            base.is_virtual = (vdisp != -1);
            info.base_classes.push_back(base);
        }
    }

    return info;
}

} // namespace msvc_rtti

// Main RTTI parser interface
inline InheritanceInfo parse_vtable_rtti(ea_t vtable_addr, bool is_windows) {
    InheritanceInfo info;

    const int ptr_size = get_ptr_size();

    if (is_windows) {
        // MSVC: COL is at vtable - 1*ptr_size
        ea_t col_addr = read_ptr(vtable_addr - ptr_size);
        if (col_addr != BADADDR) {
            // Get class name from vtable symbol
            qstring vt_name;
            std::string class_name;
            if (get_name(&vt_name, vtable_addr)) {
                const char* name = vt_name.c_str();
                if (strncmp(name, "??_7", 4) == 0) {
                    const char* end = strstr(name, "@@6B@");
                    if (end) {
                        class_name.assign(name + 4, end - name - 4);
                    }
                }
            }

            info = msvc_rtti::parse_msvc_col(col_addr, class_name);
        }
    } else {
        // GCC: Try 3 most common offsets
        // IDA's _ZTV symbol can point to different parts of the vtable struct
        ea_t typeinfo_candidates[3];
        typeinfo_candidates[0] = read_ptr(vtable_addr + ptr_size);      // Most common: +1
        typeinfo_candidates[1] = read_ptr(vtable_addr - ptr_size);      // Alternative: -1
        typeinfo_candidates[2] = read_ptr(vtable_addr - 2 * ptr_size);  // Standard GCC: -2

        // Get class name from vtable symbol
        qstring vt_name;
        std::string class_name;
        if (get_name(&vt_name, vtable_addr)) {
            qstring demangled;
            if (demangle_name(&demangled, vt_name.c_str(), MNG_NODEFINIT) > 0) {
                const char* dem = demangled.c_str();
                // Try both "vtable for " and "vtable for'" (IDA demangle format)
                const char* vtable_pos = strstr(dem, "vtable for ");
                if (!vtable_pos) {
                    vtable_pos = strstr(dem, "vtable for'");
                }

                if (vtable_pos) {
                    // Skip "vtable for " or "vtable for'"
                    const char* start = vtable_pos + 11; // "vtable for "
                    if (*start == '\'') start++; // Skip opening quote if present

                    class_name = start;

                    // Remove trailing quote if present
                    size_t len = class_name.length();
                    if (len > 0 && class_name[len-1] == '\'') {
                        class_name = class_name.substr(0, len-1);
                    }
                }
            }
        }

        // Try all candidates and use the one that gives valid results
        for (int i = 0; i < 3; ++i) {
            ea_t typeinfo_addr = typeinfo_candidates[i];
            if (typeinfo_addr == BADADDR || !is_mapped(typeinfo_addr)) {
                continue;
            }

            // Try parsing
            InheritanceInfo test_info = gcc_rtti::parse_gcc_typeinfo(typeinfo_addr, class_name);

            // If we got base classes, use this one
            if (!test_info.base_classes.empty()) {
                info = test_info;
                break;
            }

            // If this is the last attempt, use it anyway (even if empty)
            if (i == 2) {
                info = test_info;
            }
        }
    }

    return info;
}

// Cache for RTTI parsing results
static std::map<ea_t, InheritanceInfo> g_rtti_cache;

inline const InheritanceInfo& get_inheritance_info(ea_t vtable_addr, bool is_windows) {
    auto it = g_rtti_cache.find(vtable_addr);
    if (it != g_rtti_cache.end()) {
        return it->second;
    }

    InheritanceInfo info = parse_vtable_rtti(vtable_addr, is_windows);
    g_rtti_cache[vtable_addr] = info;
    return g_rtti_cache[vtable_addr];
}

inline void clear_rtti_cache() {
    g_rtti_cache.clear();
}

} // namespace rtti_parser
