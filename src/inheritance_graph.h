#pragma once
#include <ida.hpp>
#include <graph.hpp>
#include <kernwin.hpp>
#include <moves.hpp>
#include <map>
#include <set>
#include <string>
#include "rtti_parser.h"
#include "vtable_comparison.h"
#include "vtable_utils.h"

namespace inheritance_graph {

// Simple graph data structure (not inheriting from interactive_graph_t)
struct graph_data_t {
    std::map<int, std::string> node_labels;
    std::map<int, ea_t> node_vtables;
    std::map<int, uint32> node_colors;
    std::map<int, std::vector<int>> edges;  // node -> children
    int node_count = 0;
    std::string current_class;
    int current_node = -1;

    int add_node(const std::string& label, ea_t vtable_addr, uint32 bg_color) {
        int node = node_count++;
        node_labels[node] = label;
        node_vtables[node] = vtable_addr;
        node_colors[node] = bg_color;
        edges[node] = std::vector<int>();
        return node;
    }

    void add_edge(int from, int to) {
        edges[from].push_back(to);
    }

    ea_t get_vtable(int node) const {
        auto it = node_vtables.find(node);
        return it != node_vtables.end() ? it->second : BADADDR;
    }
};

inline void collect_ancestors(
    const std::string& class_name,
    const std::map<std::string, const VTableInfo*>& vtable_map,
    std::set<std::string>& lineage)
{
    auto it = vtable_map.find(class_name);
    if (it == vtable_map.end()) return;

    const VTableInfo* vt = it->second;
    if (!vt->base_classes.empty()) {
        for (const auto& base : vt->base_classes) {
            if (lineage.insert(base).second) {  // If newly inserted
                collect_ancestors(base, vtable_map, lineage);  // Recurse up
            }
        }
    }
}

inline void collect_descendants(
    const std::string& class_name,
    const std::vector<VTableInfo>* all_vtables,
    std::set<std::string>& lineage)
{
    for (const auto& vt : *all_vtables) {
        // If this vtable has class_name as a parent
        for (const auto& base : vt.base_classes) {
            if (base == class_name) {
                if (lineage.insert(vt.class_name).second) {  // If newly inserted
                    collect_descendants(vt.class_name, all_vtables, lineage);  // Recurse down
                }
                break;
            }
        }
    }
}


// Callback for graph events
static ssize_t idaapi graph_callback(void *ud, int code, va_list va) {
    graph_data_t *data = (graph_data_t *)ud;

    switch (code) {
        case grcode_user_refresh:
            return 1;

        case grcode_clicked: {
            graph_viewer_t *gv = va_arg(va, graph_viewer_t *);
            selection_item_t *item = va_arg(va, selection_item_t *);

            if (item && item->is_node) {
                ea_t vtable_addr = data->get_vtable(item->node);
                if (vtable_addr != BADADDR) {
                    jumpto(vtable_addr);
                }
            }
            return 0;
        }

        case grcode_dblclicked: {
            graph_viewer_t *gv = va_arg(va, graph_viewer_t *);
            selection_item_t *item = va_arg(va, selection_item_t *);

            if (item && item->is_node) {
                viewer_center_on(gv, item->node);
            }
            return 0;
        }

        case grcode_destroyed: {
            // Graph destroyed - clean up data (each graph is independent now)
            if (data) {
                delete data;
            }
            return 0;
        }

        default:
            break;
    }

    return 0;
}


inline void calculate_inheritance_stats(
    ea_t child_vtable_addr,
    ea_t parent_vtable_addr,
    bool is_windows,
    const std::vector<ea_t>& sorted_vtables,
    int& inherited,
    int& overridden,
    int& new_funcs)
{
    inherited = 0;
    overridden = 0;
    new_funcs = 0;

    if (child_vtable_addr == BADADDR || parent_vtable_addr == BADADDR) {
        return;
    }

    // Use the proven comparison code from vtable_comparison.h
    auto comparison = vtable_comparison::compare_vtables(
        child_vtable_addr,
        parent_vtable_addr,
        is_windows,
        sorted_vtables
    );

    inherited = comparison.inherited_count;
    overridden = comparison.overridden_count;
    new_funcs = comparison.new_virtual_count;
}

inline void build_padded_line(char* out, int out_size,
                               const char* label, const char* value,
                               int line_width) {
    int label_len = strlen(label);
    int value_len = strlen(value);
    int padding = line_width - 4 - label_len - value_len;  // -4 for "  " on each end
    if (padding < 1) padding = 1;

    // Build: "  " + label + padding spaces + value + "  "
    char* p = out;
    p += qsnprintf(p, out_size, "  %s", label);
    for (int i = 0; i < padding && (p - out) < out_size - 3; i++) {
        *p++ = ' ';
    }
    qsnprintf(p, out_size - (p - out), "%s  ", value);
}

inline void show_inheritance_graph(
    const std::string& class_name,
    ea_t vtable_addr,
    bool is_windows,
    const std::vector<VTableInfo>* all_vtables)
{
    TWidget* existing = find_widget("Inheritance Lineage");
    if (existing) {
        close_widget(existing, WCLS_DONT_SAVE_SIZE);
    }

    if (!all_vtables || all_vtables->empty()) {
        warning("No vtables available");
        return;
    }

    show_wait_box("Building lineage...");

    // Build vtable map and sorted addresses for comparison
    std::map<std::string, const VTableInfo*> vtable_map;
    std::vector<ea_t> sorted_vtables;
    sorted_vtables.reserve(all_vtables->size());
    for (const auto& vt : *all_vtables) {
        vtable_map[vt.class_name] = &vt;
        sorted_vtables.push_back(vt.address);
    }
    std::sort(sorted_vtables.begin(), sorted_vtables.end());

    // Collect lineage: selected class + all ancestors + all descendants
    std::set<std::string> lineage;
    lineage.insert(class_name);  // Add selected class

    size_t before_ancestors = lineage.size();
    collect_ancestors(class_name, vtable_map, lineage);  // Add all parents up to root
    size_t ancestors_count = lineage.size() - before_ancestors;

    size_t before_descendants = lineage.size();
    collect_descendants(class_name, all_vtables, lineage);  // Add all children down
    size_t descendants_count = lineage.size() - before_descendants;

    // Create graph data with ONLY lineage classes
    graph_data_t *data = new graph_data_t();
    std::map<std::string, int> class_to_node;

    // Colors - Medium-dark backgrounds with good text contrast
    using namespace vtable_utils;
    const uint32 NORMAL_COLOR = GRAPH_NORMAL;     // Medium-dark tan (good contrast)
    const uint32 SELECTED_COLOR = GRAPH_SELECTED; // Lighter tan for selection highlight
    const uint32 ABSTRACT_COLOR = GRAPH_ABSTRACT; // Medium purple (good contrast)

    // Add nodes for lineage classes only with MULTILINE labels
    for (const std::string& cls : lineage) {
        auto it = vtable_map.find(cls);
        if (it == vtable_map.end()) continue;

        const VTableInfo* vt = it->second;

        // Build structured label with dynamic width based on class name length
        char label[1024];
        char lines[10][256];
        int line_count = 0;
        bool is_abstract = (vt->pure_virtual_count > 0);

        // Line 0: Class name with SELECTED marker
        bool is_selected = (cls == class_name);
        if (is_selected && is_abstract) {
            qsnprintf(lines[line_count++], 256, "  %s [abstract] (SELECTED)  ", cls.c_str());
        } else if (is_selected) {
            qsnprintf(lines[line_count++], 256, "  %s (SELECTED)  ", cls.c_str());
        } else if (is_abstract) {
            qsnprintf(lines[line_count++], 256, "  %s [abstract]  ", cls.c_str());
        } else {
            qsnprintf(lines[line_count++], 256, "  %s  ", cls.c_str());
        }

        // Calculate actual line width based on class name (minimum 50, max from name)
        int name_len = strlen(lines[0]);
        const int LINE_WIDTH = (name_len > 50) ? name_len : 50;

        // Pad class name line to LINE_WIDTH
        if (name_len < LINE_WIDTH) {
            for (int i = name_len; i < LINE_WIDTH && i < 255; i++) {
                lines[0][i] = ' ';
            }
            lines[0][LINE_WIDTH] = '\0';
        }

        // Line 1: Separator (dynamic width matching LINE_WIDTH)
        int sep_idx = 0;
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx++] = ' ';
        for (int i = 2; i < LINE_WIDTH - 2 && sep_idx < 255; i++) {
            lines[line_count][sep_idx++] = '-';
        }
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx] = '\0';
        line_count++;

        // Line 2: Address (label left, value right) - 9-char fixed-width labels
        char addr_val[32];
        qsnprintf(addr_val, sizeof(addr_val), "0x%llX", (unsigned long long)vt->address);
        build_padded_line(lines[line_count++], 256, "Addr    :", addr_val, LINE_WIDTH);

        // Line 3: Function count
        char funcs_val[32];
        if (is_abstract) {
            qsnprintf(funcs_val, sizeof(funcs_val), "%d (%d pure)", vt->func_count, vt->pure_virtual_count);
        } else {
            qsnprintf(funcs_val, sizeof(funcs_val), "%d", vt->func_count);
        }
        build_padded_line(lines[line_count++], 256, "Funcs   :", funcs_val, LINE_WIDTH);

        // Line 4: Parent class
        char parent_val[128];
        ea_t parent_vtable_addr = BADADDR;
        if (!vt->base_classes.empty()) {
            const char* parent_name = vt->base_classes[0].c_str();
            if (vt->base_classes.size() > 1) {
                qsnprintf(parent_val, sizeof(parent_val), "%s (+%d)", parent_name, (int)vt->base_classes.size() - 1);
            } else {
                qsnprintf(parent_val, sizeof(parent_val), "%s", parent_name);
            }
            // Get parent vtable address for inheritance stats
            auto parent_it = vtable_map.find(vt->base_classes[0]);
            if (parent_it != vtable_map.end()) {
                parent_vtable_addr = parent_it->second->address;
            }
        } else {
            qsnprintf(parent_val, sizeof(parent_val), "(root)");
        }
        build_padded_line(lines[line_count++], 256, "Parent  :", parent_val, LINE_WIDTH);

        // Line 5: Derived count (Kids)
        char kids_val[16];
        qsnprintf(kids_val, sizeof(kids_val), "%d", vt->derived_count);
        build_padded_line(lines[line_count++], 256, "Kids    :", kids_val, LINE_WIDTH);

        // Lines 6-8: Inheritance stats (if has parent) - NO separator, just data
        if (parent_vtable_addr != BADADDR) {
            int inherited = 0, overridden = 0, new_funcs = 0;
            calculate_inheritance_stats(vt->address, parent_vtable_addr, vt->is_windows,
                                       sorted_vtables, inherited, overridden, new_funcs);

            // Add inheritance breakdown as separate lines (no separator before)
            char inh_val[16], ovr_val[16], new_val[16];
            qsnprintf(inh_val, sizeof(inh_val), "%d", inherited);
            qsnprintf(ovr_val, sizeof(ovr_val), "%d", overridden);
            qsnprintf(new_val, sizeof(new_val), "%d", new_funcs);

            build_padded_line(lines[line_count++], 256, "Inherit :", inh_val, LINE_WIDTH);
            build_padded_line(lines[line_count++], 256, "Override:", ovr_val, LINE_WIDTH);
            build_padded_line(lines[line_count++], 256, "New     :", new_val, LINE_WIDTH);
        }

        // Combine all lines
        label[0] = '\0';
        for (int i = 0; i < line_count; i++) {
            if (i > 0) qstrncat(label, "\n", sizeof(label) - strlen(label) - 1);
            qstrncat(label, lines[i], sizeof(label) - strlen(label) - 1);
        }

        uint32 color = (cls == class_name) ? SELECTED_COLOR :
                       is_abstract ? ABSTRACT_COLOR : NORMAL_COLOR;

        int node = data->add_node(label, vt->address, color);
        class_to_node[cls] = node;
    }

    // Add edges (inheritance relationships) for lineage classes
    for (const std::string& cls : lineage) {
        auto it = vtable_map.find(cls);
        if (it == vtable_map.end()) continue;

        int child_node = class_to_node[cls];
        for (const auto& base : it->second->base_classes) {
            auto parent_it = class_to_node.find(base);
            if (parent_it != class_to_node.end()) {
                data->add_edge(parent_it->second, child_node);  // parent -> child
            }
        }
    }

    // Create interactive graph
    interactive_graph_t* graph = create_interactive_graph(10000 + rand());

    // Add nodes (first just add them, then set info)
    for (int i = 0; i < data->node_count; i++) {
        graph->resize(i + 1);  // Ensure graph has space for node i
    }

    // Set node info (text, color, address)
    for (int i = 0; i < data->node_count; i++) {
        node_info_t ni;
        ni.text = data->node_labels[i].c_str();
        ni.ea = data->node_vtables[i];
        ni.bg_color = data->node_colors[i];
        set_node_info(graph->gid, i, ni, NIF_TEXT | NIF_BG_COLOR | NIF_EA);
    }

    // Add edges
    for (const auto& [from, tos] : data->edges) {
        for (int to : tos) {
            edge_info_t ei;
            graph->add_edge(from, to, &ei);
        }
    }

    // Create viewer and display
    graph_viewer_t* viewer = create_graph_viewer("Inheritance Lineage", graph->gid, graph_callback, data, 0);
    set_viewer_graph(viewer, graph);

    // Use DIGRAPH layout for better packing and fewer line crossings
    graph->del_custom_layout();
    graph->create_digraph_layout();

    display_widget(viewer, WOPN_DP_TAB | WOPN_PERSIST);
    refresh_viewer(viewer);

    // Set zoom to 100% and center on selected class
    int selected_node = class_to_node[class_name];
    viewer_center_on(viewer, selected_node);

    graph_location_info_t gli;
    gli.zoom = 1.0;  // 100% zoom
    viewer_set_gli(viewer, &gli, 0);

    refresh_viewer(viewer);

    hide_wait_box();
}

} // namespace inheritance_graph
