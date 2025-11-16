#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <auto.hpp>
#include <vector>

namespace smart_annotator {

inline int detect_vfunc_start_offset(ea_t vtable_addr, bool is_windows) {
    if (is_windows)
        return 0;

    int ptr_size = inf_is_64bit() ? 8 : 4;

    for (int i = 0; i < 4; ++i) {
        ea_t entry_addr = vtable_addr + (i * ptr_size);

        if (!is_mapped(entry_addr))
            continue;

        ea_t ptr_val = ptr_size == 8 ? get_qword(entry_addr) : get_dword(entry_addr);

        segment_t* seg = getseg(ptr_val);
        if (seg && (seg->perm & SEGPERM_EXEC))
            return i;
    }

    return 2;
}

// Validate if address is a function pointer
inline bool is_valid_function_pointer(ea_t addr) {
    if (addr == 0 || addr == BADADDR)
        return false;

    if (!is_mapped(addr))
        return false;

    // Check executable segment
    segment_t* seg = getseg(addr);
    if (!seg || !(seg->perm & SEGPERM_EXEC))
        return false;

    // Already code?
    if (is_code(get_flags(addr)))
        return true;

    // Try function prologue detection (x86/x64)
    uint8 byte = get_byte(addr);
    if (byte == 0x55 || byte == 0x48 || byte == 0x40 || byte == 0x41)
        return true;

    return false;
}

// Find next vtable (boundary detection)
inline ea_t find_next_vtable(ea_t current_vtable, const std::vector<ea_t>& all_vtable_addrs) {
    ea_t next = BADADDR;

    for (ea_t addr : all_vtable_addrs) {
        if (addr > current_vtable && (next == BADADDR || addr < next)) {
            next = addr;
        }
    }

    return next;
}

// Annotate vtable with indices
inline int annotate_vtable(ea_t vtable_addr, bool is_windows, const std::vector<ea_t>& all_vtables) {
    int ptr_size = inf_is_64bit() ? 8 : 4;
    int start_offset = detect_vfunc_start_offset(vtable_addr, is_windows);
    int annotated_count = 0;
    int consecutive_invalid = 0;
    const int max_consecutive_invalid = 2;
    const int max_entries = 1024;

    ea_t next_vtable = find_next_vtable(vtable_addr, all_vtables);
    int max_check = max_entries;

    if (next_vtable != BADADDR)
        max_check = std::min(max_entries, (int)((next_vtable - vtable_addr) / ptr_size));

    int vfunc_index = 0;

    for (int i = start_offset; i < max_check; ++i) {
        ea_t entry_addr = vtable_addr + (i * ptr_size);

        if (!is_mapped(entry_addr))
            break;

        ea_t func_ptr = ptr_size == 8 ? get_qword(entry_addr) : get_dword(entry_addr);

        for (ea_t other_vtable : all_vtables) {
            if (entry_addr == other_vtable && entry_addr != vtable_addr)
                goto done;
        }

        if (func_ptr == 0 || func_ptr == BADADDR) {
            consecutive_invalid++;
            if (consecutive_invalid >= max_consecutive_invalid)
                break;
            continue;
        }

        if (!is_valid_function_pointer(func_ptr)) {
            qstring name;
            get_name(&name, func_ptr);
            if (name.find("_ZTI") != qstring::npos || name.find("typeinfo") != qstring::npos) {
                consecutive_invalid++;
                if (consecutive_invalid >= max_consecutive_invalid)
                    break;
                continue;
            }

            consecutive_invalid++;
            if (consecutive_invalid >= max_consecutive_invalid)
                break;
            continue;
        }

        consecutive_invalid = 0;

        if (!is_code(get_flags(func_ptr)))
            add_func(func_ptr);

        // Comment at function
        qstring func_cmt;
        get_cmt(&func_cmt, func_ptr, false);
        std::string new_cmt = "vtable index: " + std::to_string(vfunc_index);

        if (func_cmt.find("vtable index") == qstring::npos) {
            if (!func_cmt.empty())
                func_cmt.append("\n");
            func_cmt.append(new_cmt.c_str());
            set_cmt(func_ptr, func_cmt.c_str(), false);
        }

        // Comment at vtable entry
        std::string entry_cmt = "vtable index #" + std::to_string(vfunc_index);
        set_cmt(entry_addr, entry_cmt.c_str(), false);

        annotated_count++;
        vfunc_index++; // Increment only for successfully annotated functions
    }

done:
    msg("[VTableExplorer] Annotation complete: %d functions\n", annotated_count);
    return annotated_count;
}

} // namespace smart_annotator
