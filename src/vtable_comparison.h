#pragma once
#include <ida.hpp>
#include <vector>
#include <string>
#include <map>
#include "rtti_parser.h"
#include "smart_annotator.h"
#include "vtable_utils.h"

namespace vtable_comparison {

enum class OverrideStatus {
    INHERITED,      // Same function as base class
    OVERRIDDEN,     // Different function than base class
    NEW_VIRTUAL,    // Function exists only in derived class
    PURE_TO_IMPL,   // Base has pure virtual, derived has implementation
    IMPL_TO_PURE    // Base has implementation, derived has pure virtual (rare)
};

struct ComparisonEntry {
    int index;
    ea_t derived_entry_addr;
    ea_t derived_func_ptr;
    ea_t base_entry_addr;
    ea_t base_func_ptr;
    OverrideStatus status;
    bool is_pure_virtual_base;
    bool is_pure_virtual_derived;
    std::string base_func_name;
    std::string derived_func_name;
};

struct VTableComparison {
    std::string derived_class;
    std::string base_class;
    ea_t derived_vtable;
    ea_t base_vtable;
    std::vector<ComparisonEntry> entries;
    int inherited_count;
    int overridden_count;
    int new_virtual_count;
};

inline std::string get_function_name(ea_t func_ptr) {
    if (func_ptr == BADADDR || !func_ptr) return "";

    qstring name;
    if (get_name(&name, func_ptr)) {
        return std::string(name.c_str());
    }

    return "";
}

inline VTableComparison compare_vtables(
    ea_t derived_vtable,
    ea_t base_vtable,
    bool is_windows,
    const std::vector<ea_t>& sorted_vtables,
    const std::string& derived_class = "",
    const std::string& base_class = "")
{
    VTableComparison result;
    result.derived_class = derived_class;
    result.base_class = base_class;
    result.derived_vtable = derived_vtable;
    result.base_vtable = base_vtable;
    result.inherited_count = 0;
    result.overridden_count = 0;
    result.new_virtual_count = 0;

    // Get vtable entries for both classes
    auto derived_entries = smart_annotator::get_vtable_entries(derived_vtable, is_windows, sorted_vtables);
    auto base_entries = smart_annotator::get_vtable_entries(base_vtable, is_windows, sorted_vtables);

    // Create map of base class functions by index
    std::map<int, smart_annotator::VTableEntry> base_map;
    for (const auto& entry : base_entries) {
        base_map[entry.index] = entry;
    }

    // Compare each derived class entry with base class
    for (const auto& derived : derived_entries) {
        ComparisonEntry comp;
        comp.index = derived.index;
        comp.derived_entry_addr = derived.entry_addr;
        comp.derived_func_ptr = derived.func_ptr;
        comp.is_pure_virtual_derived = derived.is_pure_virtual;
        comp.derived_func_name = get_function_name(derived.func_ptr);

        // Check if this index exists in base class
        auto it = base_map.find(derived.index);
        if (it != base_map.end()) {
            // Function exists in both base and derived
            const auto& base = it->second;
            comp.base_entry_addr = base.entry_addr;
            comp.base_func_ptr = base.func_ptr;
            comp.is_pure_virtual_base = base.is_pure_virtual;
            comp.base_func_name = get_function_name(base.func_ptr);

            // Determine override status
            if (comp.derived_func_ptr == comp.base_func_ptr) {
                comp.status = OverrideStatus::INHERITED;
                result.inherited_count++;
            } else {
                if (comp.is_pure_virtual_base && !comp.is_pure_virtual_derived) {
                    comp.status = OverrideStatus::PURE_TO_IMPL;
                } else if (!comp.is_pure_virtual_base && comp.is_pure_virtual_derived) {
                    comp.status = OverrideStatus::IMPL_TO_PURE;
                } else {
                    comp.status = OverrideStatus::OVERRIDDEN;
                }
                result.overridden_count++;
            }
        } else {
            // Function only exists in derived class
            comp.base_entry_addr = BADADDR;
            comp.base_func_ptr = BADADDR;
            comp.is_pure_virtual_base = false;
            comp.base_func_name = "";
            comp.status = OverrideStatus::NEW_VIRTUAL;
            result.new_virtual_count++;
        }

        result.entries.push_back(comp);
    }

    return result;
}

// Find base class vtable by class name
inline ea_t find_vtable_by_class_name(
    const std::string& class_name,
    const std::vector<VTableInfo>& all_vtables)
{
    for (const auto& vt : all_vtables) {
        if (vt.class_name == class_name) {
            return vt.address;
        }
    }
    return BADADDR;
}

inline const char* get_status_string(OverrideStatus status) {
    switch (status) {
        case OverrideStatus::INHERITED:    return "Inherited";
        case OverrideStatus::OVERRIDDEN:   return "Overridden";
        case OverrideStatus::NEW_VIRTUAL:  return "New Virtual";
        case OverrideStatus::PURE_TO_IMPL: return "Pure→Impl";
        case OverrideStatus::IMPL_TO_PURE: return "Impl→Pure";
        default: return "Unknown";
    }
}

inline uint32 get_status_text_color(OverrideStatus status) {
    using namespace vtable_utils;
    switch (status) {
        case OverrideStatus::INHERITED:    return STATUS_INHERITED;
        case OverrideStatus::OVERRIDDEN:   return STATUS_OVERRIDDEN;
        case OverrideStatus::NEW_VIRTUAL:  return STATUS_NEW_VIRTUAL;
        case OverrideStatus::PURE_TO_IMPL: return STATUS_PURE_TO_IMPL;
        case OverrideStatus::IMPL_TO_PURE: return STATUS_IMPL_TO_PURE;
        default: return DEFAULT_BG;
    }
}

} // namespace vtable_comparison
