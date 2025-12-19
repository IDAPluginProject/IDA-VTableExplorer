#pragma once
#include <ida.hpp>

// VTable Explorer - Utilities and Configuration

namespace vtable_utils {

// Configuration (validated against production data)
constexpr size_t MIN_CLASS_NAME_LENGTH = 2;
constexpr size_t MAX_CLASS_NAME_LENGTH = 256;  // safety: 3.4x (max observed: 75)
constexpr float MIN_ALNUM_RATIO = 0.6f;
constexpr int MAX_MANGLING_MARKERS = 3;
constexpr size_t MAX_COMPONENT_LENGTH = 1024;

constexpr int MAX_VTABLE_ENTRIES = 2048;       // safety: 2.4x (max observed: 866)
constexpr int CONSECUTIVE_INVALID_THRESHOLD = 5;
constexpr int DEFAULT_VFUNC_START_OFFSET = 2;
constexpr int MAX_VFUNC_SEARCH_DEPTH = 4;      // max RTTI metadata entries before vfuncs
constexpr int MAX_RTTI_STRING_LENGTH = 512;    // max RTTI name string length

constexpr size_t COMMENT_BUFFER_SIZE = 64;
constexpr size_t FUNCTION_NAME_CACHE_SIZE = 384;  // safety: 5x (max observed: 75)
constexpr size_t INDEX_CACHE_SIZE = 16;
constexpr size_t ADDRESS_CACHE_SIZE = 32;
constexpr size_t BASE_CLASSES_DISPLAY_SIZE = 256;

constexpr size_t VTABLE_RESERVE_RATIO = 100;
constexpr size_t ENTRY_RESERVE_SIZE = 64;

// X86/X64 Function Prologue Opcodes
constexpr uint8 OPCODE_PUSH_RBP = 0x55;   // push rbp/ebp
constexpr uint8 OPCODE_REX_W = 0x48;      // REX.W prefix
constexpr uint8 OPCODE_REX = 0x40;        // REX prefix base
constexpr uint8 OPCODE_REX_B = 0x41;      // REX.B prefix

// Color Constants (IDA uses BGR format, not RGB!)
constexpr uint32 GRAPH_NORMAL   = 0x706050;
constexpr uint32 GRAPH_SELECTED = 0xA08070;
constexpr uint32 GRAPH_ABSTRACT = 0x806080;

constexpr uint32 STATUS_INHERITED    = 0xA0A0A0;
constexpr uint32 STATUS_OVERRIDDEN   = 0x80D080;
constexpr uint32 STATUS_NEW_VIRTUAL  = 0x8080D0;
constexpr uint32 STATUS_PURE_TO_IMPL = 0x80D0D0;
constexpr uint32 STATUS_IMPL_TO_PURE = 0xD08080;

constexpr uint32 CLASS_PURE_VIRTUAL      = 0xD08080;
constexpr uint32 CLASS_MULTIPLE_INHERIT  = 0xD0A080;
constexpr uint32 CLASS_VIRTUAL_INHERIT   = 0x8080D0;

constexpr uint32 DEFAULT_BG = 0xFFFFFF;

// Formatting Utilities
inline void format_address(char* buf, size_t size, ea_t addr) {
    qsnprintf(buf, size, "0x%llX", (unsigned long long)addr);
}

inline void format_sub_address(char* buf, size_t size, ea_t addr) {
    qsnprintf(buf, size, "sub_%llX", (unsigned long long)addr);
}

inline void format_index(char* buf, size_t size, int index) {
    qsnprintf(buf, size, "%d", index);
}

inline void format_function(char* buf, size_t size, ea_t func_ptr) {
    qstring func_name;
    if (get_name(&func_name, func_ptr) && func_name.length() > 0) {
        qsnprintf(buf, size, "%s", func_name.c_str());
    } else {
        format_address(buf, size, func_ptr);
    }
}

// Pointer Size Utilities
inline int get_ptr_size() {
    static int ptr_size = inf_is_64bit() ? 8 : 4;
    return ptr_size;
}

inline ea_t read_ptr(ea_t addr) {
    if (!is_mapped(addr)) return BADADDR;
    return get_ptr_size() == 8 ? get_qword(addr) : get_dword(addr);
}

inline int32 read_int32(ea_t addr) {
    if (!is_mapped(addr)) return 0;
    return get_dword(addr);
}

} // namespace vtable_utils
