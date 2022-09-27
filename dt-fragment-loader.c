// SPDX-License-Identifier: GPL-2.0
/*
 * A module for advanced device tree modification.
 *
 * Copyright (c) 2015-2016, NVIDIA CORPORATION.  All rights reserved.
 * Author: Laxman Dewangan <ldewangan@nvidia.com>
 *
 * Copyright (c) 2019, D3 Engineering  All rights reserved.
 * Author: Tyler Hart <thart@d3engineering.com>
 * Author: Christopher White <cwhite@d3engineering.com>
 *
 * Copyright (c) 2022, Starry Inc.  All rights reserved.
 * Author: Luna Hart (nitepone) <tihart@starry.com>
 */

#define MODULE_NAME "dt-fragment-loader"
#define pr_fmt(fmt) "%s: " fmt, MODULE_NAME

#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#define DEVICETREE_PROPERTY_NAME "active-fragments"
#define DEVICETREE_FRAGMENT_ROOT "/dt-fragments"

/**
 * An error handling macro to wrap `of/dynamic.c` errors.
 *
 * Any `of/dynamic` error is "fatal". And must be logged verbosely.
 * Thus, we do a pr_err. Then set the error to a standard -EFAULT.
 */
#define TRY_OR_PRERR_AND_GOTO_EFAULT(m_fn, m_ret, m_clean) \
    do { \
        if ((m_ret = m_fn)) { \
            pr_err("%s: calling '%s' failed with: %d", __func__, "m_fn", m_ret); \
            m_ret = -EFAULT; \
            goto m_clean; \
        } \
    } while (0)


static char* active_fragments = NULL;
module_param(active_fragments, charp, 0444);
MODULE_PARM_DESC(
        active_fragments,
        "List of active fragments as a comma seperated string"
);


/**
 * Identifying information for a fragment. To be used for identifying what
 * fragments to activate.
 *
 * @param_str: String representation of param (allocated on heap)
 * @location: An enumeration of unique hardware locations (defined by DT)
 * @compat: An enumeration of compatible hardware of a location (defined by DT)
 * @parse_error: If non-zero, `location` and `compat` should be ignored.
 *               Indicates sprintf failing to parse these params from the
 *               current fragment_id value.
 * @list: the list_head for linux linked list usage
 */
struct dfl_fragment_id {
    char* param_str;
    u32 location;
    u32 compat;
    bool parse_error;
    struct list_head list;
};


/**
 * Free a struct dfl_fragment_id and its contained string.
 */
static void dfl_fid_free(struct dfl_fragment_id *fid)
{
    if (!fid) {
        return;
    }

    kfree(fid->param_str);
    kfree(fid);
}


/**
 * Free a full linked list of struct dfl_fragment_id.
 */
static void dfl_fid_free_list(struct list_head* fid_list)
{
    struct dfl_fragment_id* fid;
    struct dfl_fragment_id* n;
    list_for_each_entry_safe(fid, n, fid_list, list) {
        dfl_fid_free(fid);
    }
}


/**
 * Private data to be passed around inside dfl as we apply dt fragments.
 * Namely, Our fragment root and enumerations of "fragment_ids" to apply.
 * @fragment_root: The root node of our dt fragments.
 * @active_mod_fids: fragment_ids for active fragments derived from module
 *                    cmdline.
 * @active_dtb_fids: fragment_ids for active fragments derived from the
 *                    device-tree override parameter.
 */
struct dfl_priv {
    struct device_node* fragment_root;
    struct list_head active_mod_fids;
    struct list_head active_dtb_fids;
};


/**
 * Our approximation of a fragment "override" operation's "overlay" tree.
 * Since we are *moving* nodes, the "overlay" node in the fragment will
 * become untraverseable rather quickly.
 *
 * This "vine" will provide us references to nodes within the old tree.
 * Keeping track of where and what order they should be applied.
 *
 * We should **never** allocate memory for `node` or `target`.
 *
 * @node: the of node to move.
 * @target: the destination of the of node.
 * @list: the list_head for linux linked list usage
 */
struct dfl_vine {
    struct device_node* node;
    struct device_node* target;
    struct list_head list;
};


/**
 * Frees an entire allocated list of vines.
 */
static void dfl_vine_free_list(struct list_head* vine_list)
{
    struct dfl_vine* vine;
    struct dfl_vine* n;
    list_for_each_entry_safe(vine, n, vine_list, list) {
        kfree(vine);
    }
}


/**
 * Helper function for `dfl_vine_new`.
 */
static int dfl_vine_new_recurse(
        struct list_head* vine_list,
        struct device_node* cur_root,
        struct device_node* cur_target
){
    struct device_node* cur_child = NULL;
    struct dfl_vine* new_vine = NULL;
    int ret = 0;
    if (!cur_root || !cur_target || !vine_list) {
        return -EINVAL;
    }

    for_each_child_of_node(cur_root, cur_child) {
        new_vine = kzalloc(sizeof(*(new_vine)), GFP_KERNEL);
        if (new_vine == NULL) {
            return -ENOMEM;
        }
        new_vine->target = cur_target;
        new_vine->node = cur_child;
        list_add(&new_vine->list, vine_list);
        // Note, we _always_ want the children of cur_child to be
        // attached to cur_child via the "target" param.
        // Attaching nodes with `of/dynamic.c` will strip off all children.
        // So we gotta reattach them _after_ attaching the parent.
        // (which should be accomplished by appending them to the vine
        // after their parent)
        ret = dfl_vine_new_recurse(vine_list, cur_child, cur_child);
        if (ret) {
            return ret;
        }
    }

    return 0;
}


/**
 * Constructs a `vine` linked list from a given root node and target.
 */
static int dfl_vine_new(
        struct list_head* vine_list,
        struct device_node* overlay_root,
        struct device_node* in_tree_target
){
    int ret = 0;

    if (vine_list == NULL || overlay_root == NULL || in_tree_target == NULL) {
        return -EINVAL;
    }

    ret = dfl_vine_new_recurse(vine_list, overlay_root, in_tree_target);
    if (ret) {
        dfl_vine_free_list(vine_list);
        return ret;
    }

    return 0;
}


/**
 * Creates a changeset to detach all `node`'s in a dfl_vine from the device
 * tree; and immediately applies it.
 */
static int dfl_detach_nodes_on_vine(struct list_head* vine_list)
{
    struct of_changeset detach_cs;
    struct dfl_vine* vine;
    int ret;
    if (vine_list == NULL) {
        return -EINVAL;
    }

    of_changeset_init(&detach_cs);
    list_for_each_entry (vine, vine_list, list) {
        if (vine->node == NULL || vine->target == NULL) {
            pr_err("Malformed vine provided to %s!\n", __func__);
            ret = -EINVAL;
            goto cleanup;
        }
        TRY_OR_PRERR_AND_GOTO_EFAULT(
                of_changeset_detach_node(&detach_cs, vine->node),
                ret,
                cleanup);
    }
    TRY_OR_PRERR_AND_GOTO_EFAULT(
            of_changeset_apply(&detach_cs),
            ret,
            cleanup);

cleanup:
    if (ret) {
        pr_err("Failed to apply a vine dettach changeset!\n");
    }
    of_changeset_destroy(&detach_cs);
    return ret;
}


/**
 * Creates a changeset to attach all `node`'s in a dfl_vine to the device
 * tree; and immediately applies it.
 */
static int dfl_attach_nodes_on_vine(struct list_head* vine_list)
{
    struct of_changeset attach_cs;
    struct device_node* child;
    struct dfl_vine* vine;
    int ret;
    if (vine_list == NULL) {
        return -EINVAL;
    }

    of_changeset_init(&attach_cs);
    list_for_each_entry(vine, vine_list, list) {
        if (vine->node == NULL || vine->target == NULL) {
            pr_err("Malformed vine provided to %s!\n", __func__);
            ret = -EINVAL;
            goto cleanup;
        }
        for_each_child_of_node(vine->target, child) {
            /*
             * XXX(nitepone): We must prevent moving nodes that have name
             *                collisions with existing children of the target.
             *
             * This is important because we can not properly handle references
             * by phandle that exist elsewhere in the tree.
             *
             * Specifically, there is no clean way to ensure that when merging
             * our "out of tree" node from the overlay, and existing "in tree"
             * node, that properties referencing their phandles are
             * appropriately converted.
             *
             * For example. If a node (node X) in a fragment overlay operation
             * references another node (node A) in the same overlay. Given a
             * case where "node A" collides with an existing "in tree" node
             * with the same name (node B), and there is an "in tree" node
             * that refers to "node B" (node Z).
             * Since we effectively "merge" node A and node B into a single
             * node, the references to A and B from nodes X and Z must be
             * updated to point at the merged node.
             * However, device tree properties that use phandle references
             * are stored as u32 values. The only way to get context that a
             * value is a phandle, is to reference how each property is
             * used from the driver.
             */
            if (!strcmp(vine->node->full_name, child->full_name)) {
                pr_err("Failure moving node '%s' into target '%s'\n",
                        vine->node->full_name,
                        vine->target->full_name);
                pr_err("A node of the same name exists in the target!\n");
                pr_err("Aborting, as this is not a supported operation!\n");
                ret = -EINVAL;
                goto cleanup;
            }
        }
        // manually set the parent of our device_node to attach..
        vine->node->parent = vine->target;
        TRY_OR_PRERR_AND_GOTO_EFAULT(
                of_changeset_attach_node(&attach_cs, vine->node),
                ret,
                cleanup);
    }
    TRY_OR_PRERR_AND_GOTO_EFAULT(
            of_changeset_apply(&attach_cs),
            ret,
            cleanup);

cleanup:
    if (ret) {
        pr_err("Failed to apply a vine attach changeset!\n");
    }
    of_changeset_destroy(&attach_cs);
    return ret;
}


/**
 * Moves all children of `source` to `target`.
 */
static int dfl_move_node_children(
        struct device_node* source,
        struct device_node* target
){
    LIST_HEAD(vine_list);
    int ret = 0;

    if (source == NULL || target == NULL) {
        return -EINVAL;
    }

    if (of_get_child_count(source) <= 0) {
        pr_debug("No children to move in '%s', skipping\n", source->full_name);
        return 0;
    }

    ret = dfl_vine_new(&vine_list, source, target);
    if (ret) {
        goto cleanup;
    }
    ret = dfl_detach_nodes_on_vine(&vine_list);
    if (ret) {
        goto cleanup;
    }
    ret = dfl_attach_nodes_on_vine(&vine_list);
    if (ret) {
        goto cleanup;
    }

cleanup:
    dfl_vine_free_list(&vine_list);
    return ret;
}


/**
 * Helper function for `dfl_copy_node_props` to catch "ignored" dt properties.
 *
 * These ignored properties are dtb metadata that we don't want to propegate
 * to the target node.
 */
static bool dfl_copy_node_props_is_ignored(char* input_prop_name) {
    const char** prop_name_ptr;
    const char* ignored_props[] = {
        "name",
        "phandle",
        "linux,phandle",
        "#address-cells",
        "#size-cells"
    };

    for (
        prop_name_ptr = ignored_props;
        prop_name_ptr < (ignored_props + ARRAY_SIZE(ignored_props));
        prop_name_ptr++
    ) {
        if (strcmp(input_prop_name, *prop_name_ptr) == 0) {
            return true;
        }
    }

    return false;
}


/**
 * Copies all properties of node `overlay` into node `target`.
 */
static int dfl_copy_node_props(
        struct device_node* target,
        struct device_node* overlay
){
    struct of_changeset cs;
    struct property* prop;
    unsigned long action;
    int ret;

    if (target == NULL || overlay == NULL) {
        return -EINVAL;
    }

    of_changeset_init(&cs);

    pr_debug("Update properties from %s to %s\n", overlay->full_name,
            target->full_name);

    for_each_property_of_node(overlay, prop) {
        // skip "ignored" props
        if (dfl_copy_node_props_is_ignored(prop->name)) {
            pr_debug("  Skipped copying property %s\n", prop->name);
            continue;
        }
        action = OF_RECONFIG_ADD_PROPERTY;
        // use a different 'action' as needed if property is present
        if (of_find_property(target, prop->name, NULL) != NULL) {
            action = OF_RECONFIG_UPDATE_PROPERTY;
        }
        TRY_OR_PRERR_AND_GOTO_EFAULT(
                of_changeset_action(&cs, action, target, prop),
                ret,
                cleanup);
    }

    TRY_OR_PRERR_AND_GOTO_EFAULT(
            of_changeset_apply(&cs),
            ret,
            cleanup);

cleanup:
    if (ret) {
        pr_err("Failed to copy node props!\n");
    }
    of_changeset_destroy(&cs);

    return ret;
}


/**
 * Applies an override operation defined by `node` to the device tree.
 */
static int dfl_apply_override_operation(
        struct dfl_priv* dfl,
        struct device_node* node
){
    struct device_node* target;
    struct device_node* overlay;
    int ret;

    target = of_parse_phandle(node, "target", 0);
    if (!target) {
        pr_err("Operation %s does not have target node property\n",
                node->full_name);
        return -EINVAL;
    }
    pr_info("  Applying override operation '%s' to in tree target node '%s'\n",
            node->full_name, target->full_name);

    overlay = of_get_child_by_name(node, "_overlay_");
    if (!overlay) {
        pr_err("Operation %s does not have overlay node\n", node->full_name);
        return -EINVAL;
    }

    ret = dfl_copy_node_props(target, overlay);
    if (ret) {
        pr_err("Copying params from %s to %s failed: %d\n",
                overlay->full_name, target->full_name, ret);
        return ret;
    }

    ret = dfl_move_node_children(overlay, target);
    if (ret) {
        pr_err("Moving children from %s to %s failed: %d\n",
                overlay->full_name, target->full_name, ret);
        return ret;
    }

    return 0;
}


/**
 * Allocates and constructs a new fragment_id.
 * Note: `compat` and `location` fields will be populated in the generated
 *       fragment_id iff @param_str follows the format `l%d_c%d`, representing
 *       `compat` and `location` values respectively.
 *       The `parse_error` field will be set non-zero if this parsing fails.
 *
 *       Thus: `compat` and `location` fields should only be used for
 *             fragment_ids
 *       returned from this function that have a 0 in `parse_error`.
 *
 * @fid: The outparameter for the new fragment_id.
 * @param_str: The param string to parse to create the fragment_id.
 */
static int dfl_new_fragment_id(
        struct dfl_fragment_id** fid,
        const char* param_str
){
    int ret = 0;

    if (fid == NULL || param_str == NULL) {
        return -EINVAL;
    }

    *fid = kzalloc(sizeof(**fid), GFP_KERNEL);
    if (*fid == NULL) {
        return -ENOMEM;
    }

    (*fid)->param_str = kasprintf(GFP_KERNEL, "%s", param_str);
    if ((*fid)->param_str == NULL) {
        return -ENOMEM;
    }

    // parse string values
    ret = sscanf(
            (*fid)->param_str,
            "l%d_c%d",
            &((*fid)->location),
            &((*fid)->compat));
    (*fid)->parse_error = (ret < 2);
    if ((*fid)->parse_error) {
        pr_debug("Unable to parse loc/compat for param %s: %d\n",
                (*fid)->param_str, ret);
    }

    return 0;
}


/**
 * Determines if `new_fid` is a duplicate inside `fid_list`.
 *
 * Note: 'duplicates' are defined as fids with the same `param_str` value or
 *       the same location. (e.g. l2_c2 and l2_c3 are duplicates)
 *
 * Returns false if either parameter is NULL.
 */
static bool dfl_fid_is_duplicate(
        struct dfl_fragment_id* new_fid,
        struct list_head* fid_list
){
    struct dfl_fragment_id* existing_fid;
    bool is_duplicate = false;

    if (!new_fid || !fid_list) {
        return false;
    }

    list_for_each_entry(existing_fid, fid_list, list) {
        // check if param_str already exists
        is_duplicate =
                strcmp(existing_fid->param_str, new_fid->param_str) == 0;
        // check if a fid already impacts a location
        if (!existing_fid->parse_error && !new_fid->parse_error) {
            is_duplicate |= existing_fid->location == new_fid->location;
        }
        if (is_duplicate) {
            return true;
        }
    }

    return false;
}


/**
 * Parse a CSV string of parameters that can be parsed into fragment_ids.
 * String example "l0_c2,l1_c1,special1".
 *
 * Note: 'duplicates' are defined as fids with the same `param_str` value or
 *       the same location. (e.g. l2_c2 and l2_c3 are duplicates)
 *
 * @fid_list: a pointer to the fragment_id list to populate.
 * @param_str: the string to parse.
 * @active_fids: a list of "active" fids. for ignoring 'duplicates'.
 */
static int dfl_parse_params(
        struct list_head* fid_list,
        const char* input_param_str,
        struct list_head* active_fids
){
    struct dfl_fragment_id* new_fid = NULL;
    int ret = 0;
    const char* cur_param_token = NULL;
    bool fid_is_duplicate = false;
    char* param_str = NULL;
    char* param_str_cur = NULL;

    if (!fid_list || !list_empty(fid_list) || !input_param_str) {
        ret = -EINVAL;
        goto cleanup;
    }

    // we need a modifiable copy of the param string for strsep.
    param_str = kasprintf(GFP_KERNEL, "%s", input_param_str);
    if (param_str == NULL) {
        return -ENOMEM;
    }
    param_str_cur = param_str;

    // parse param tokens into dfl_fragment_ids
    pr_debug("Parsing params from string: %s\n", param_str);

    while ((cur_param_token = strsep(&param_str_cur, ",")) != NULL) {
        if (strlen(cur_param_token) == 0) {
            continue;
        }
        ret = dfl_new_fragment_id(&new_fid, cur_param_token);
        if (ret) {
            pr_err("Abort parse. Failed constructing fid from token, %s\n",
                    cur_param_token);
            ret = -EFAULT;
            goto cleanup;
        }
        fid_is_duplicate =
                dfl_fid_is_duplicate(new_fid, active_fids)
                || dfl_fid_is_duplicate(new_fid, fid_list);
        if (fid_is_duplicate) {
            pr_info("  Duplicate param '%s' ignored", new_fid->param_str);
            dfl_fid_free(new_fid);
            continue;
        }
        list_add(&new_fid->list, fid_list);
        pr_debug("  Found parameter %s\n",new_fid->param_str);
    }
    pr_debug("Done parsing params\n");

cleanup:
    if (ret) {
        dfl_fid_free_list(fid_list);
    }

    kfree(param_str);
    return ret;
}


/**
 * Checks whether a fragment is activated by a provided fragment_id list.
 *
 * @fid_list: kparam list to check against.
 * @node: the device-tree node of current fragment.
 * @source: name of the source of `fid_list`, for logging.
 *
 * This traverses `fid_list` and, for each fragment_id, checks whether the
 * provided fragment node `node` matches.
 *
 * Return: false on parameter error; false if no match; true if match
 */
static bool dfl_check_fragment_enabled(
        struct list_head* fid_list,
        struct device_node* node,
        const char* source
){
    struct property* prop;
    const char* bname;
    bool found = false;
    int read_err = 0;
    u32 fragment_location;
    u32 fragment_compat;
    struct dfl_fragment_id* fid;

    if (!fid_list || !node || !source) {
        return false;
    }

    pr_debug("Checking whether %s enables %s\n", source, node->full_name);

    list_for_each_entry(fid, fid_list, list) {
        // check location/compat params
        read_err |= of_property_read_u32(node, "location", &fragment_location);
        read_err |= of_property_read_u32(node, "compat", &fragment_compat);
        found = (read_err == 0) && !fid->parse_error
                && fragment_compat == fid->compat
                && fragment_location == fid->location;
        if (found) {
            pr_info("Matched fragment '%s': location(%d), compat(%d)\n",
                    node->full_name, fragment_location, fragment_compat);
            goto search_done;   // double break
        }

        // check string param
        of_property_for_each_string(node, "param", prop, bname) {
            found = strcmp(fid->param_str, bname) == 0;
            if (found) {
                pr_info("Matched fragment '%s': str_param(%s)\n",
                        node->full_name, fid->param_str);
                goto search_done;   // double break
            }
        }
    }

search_done:
    return found;
}


/**
 * Process a fragment. Iff the fragment is active, apply it to the device tree.
 *
 * The fragment is "active" if it matches a fragment_id in:
 * - The fid_list parsed from the command line, dfl->active_mod_fids
 * - The fid_list parsed from the device tree, dfl->active_dtb_fids
 *
 * @dfl: priv data for dfl
 * @node: the device-tree node of current fragment
 */
static int dfl_process_fragment(
        struct dfl_priv* dfl,
        struct device_node* node
){
    struct device_node* child_node;
    int ret = 0;
    bool found = false;

    if (of_get_child_count(node) == 0) {
        pr_err("  Fragment node %s has no operations\n", node->full_name);
        return -EINVAL;
    }

    // Check active_fragment fragment_id lists for current fragment.
    found |= dfl_check_fragment_enabled(
            &dfl->active_mod_fids,
            node,
            "commandline");
    found |= dfl_check_fragment_enabled(
            &dfl->active_dtb_fids,
            node,
            "devicetree");
    if (!found) {
        return 0;
    }

    // new fragment operations should be added here!
    for_each_child_of_node(node, child_node) {
        // using the node's `name` field over the `full_name` means we
        // don't see the reg value.
        // e.g. a node with `full_name` "override@0" has `name` "override"
        if (strcmp(child_node->name, "override") == 0) {
            ret = dfl_apply_override_operation(dfl, child_node);
            if (ret) {
                return ret;
            }
        }
        else {
            pr_info("  Unknown fragment operation node %s, skipping\n",
                    child_node->full_name);
        }
    }

    return 0;
}


static int __init dt_fragment_loader_init(void)
{
    struct dfl_priv dfl = {0};
    struct device_node* child;
    int ret = 0;
    const char* dt_active_fragments;

    pr_info("Initializing dt-fragment-loader\n");

    // prepare root node
    dfl.fragment_root = NULL;
    dfl.fragment_root = of_find_node_by_path(DEVICETREE_FRAGMENT_ROOT);
    if (!dfl.fragment_root) {
        pr_info("Not available, no root node\n");
        return 0;
    }
    if (!of_device_is_available(dfl.fragment_root)) {
        pr_info("Not available, status disabled\n");
        return 0;
    }

    // gather all fragment_ids
    INIT_LIST_HEAD(&dfl.active_mod_fids);
    if (active_fragments) { // `active_fragments` is a global module parameter
        pr_info("Parsing commandline active_fragments: %s\n",
                active_fragments);
        ret = dfl_parse_params(&dfl.active_mod_fids, active_fragments, NULL);
        if (ret) {
            pr_err("Error processing commandline active_fragments: %d\n", ret);
        }
    } else {
        pr_info("No commandline active_fragments parameter, skipping\n");
    }
    INIT_LIST_HEAD(&dfl.active_dtb_fids);
    dt_active_fragments = of_get_property(
            dfl.fragment_root,
            DEVICETREE_PROPERTY_NAME,
            NULL);
    if (dt_active_fragments) {
        pr_info("Parsing device-tree active_fragments: %s\n",
                dt_active_fragments);
        ret = dfl_parse_params(
                &dfl.active_dtb_fids,
                dt_active_fragments,
                &dfl.active_mod_fids);
        if (ret) {
            pr_err("Error processing device-tree active_fragments: %d\n", ret);
        }
    } else {
        pr_info("No device-tree active_fragments property, skipping\n");
    }

    // process fragments
    for_each_available_child_of_node(dfl.fragment_root, child) {
        ret = dfl_process_fragment(&dfl, child);
        if (ret == -EINVAL) {
            pr_err("Error parsing fragment %s (bad dt syntax?). Continuing.\n",
                    child->full_name);
        }
        else if (ret != 0) {
            pr_err("Error applying fragment %s: %d\n", child->full_name, ret);
            ret = -EINVAL;
            goto cleanup;
        }
    }

    pr_info("Device-Tree modifications complete!\n");
cleanup: // brushie brushie!
    dfl_fid_free_list(&dfl.active_mod_fids);
    dfl_fid_free_list(&dfl.active_dtb_fids);

    return ret;
}

/* Initialize the fragment loader at level 5 (fs).  This is after subsys (#4),
 * so nvmem is available, and is before device (#6), when devices
 * are initialized based on the DTB state. */
fs_initcall(dt_fragment_loader_init);

MODULE_DESCRIPTION("A driver that can apply device tree fragments.");
MODULE_AUTHOR("Laxman Dewangan <ldewangan@nvidia.com>");
MODULE_AUTHOR("Tyler Hart <thart@d3engineering.com>");
MODULE_AUTHOR("Christopher White <cwhite@d3engineering.com>");
MODULE_AUTHOR("Luna Hart <tihart@starry.com>");
MODULE_LICENSE("GPL v2");
