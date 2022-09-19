# DT Fragment Loader

A Linux Kernel Module for Advanced Device Tree Operations

# Applying Fragments

Fragments are applied based on the "active fragments" that are passed into the
module during init.

## Active Fragments

The "active fragments" string should be a comma separated list of "fragment
ids" to activate. These can either match `location` and `compat` properties of
a fragment with the format `l%d_c%d`; or just a `param` string. For example:
`"l1_c3,l2_c4,custom_param"`.

The **kernel commandline** can provide a string as a module parameter,
`active_fragments=""` or `dt_fragment_loader.active_fragments=""`.

The **device-tree** can provide an active fragments string as a property at
`/dt-fragments/active-fragments`.

We also detect **duplicate fragment ids** while parsing active fragments.
A "duplicate fragment id" is defined as a fragment id that has either the
same *location* or *param* value as another fragment id.

In event of "duplicate" fragment ids. The applied fragment id is chosen via
the following precendence:

1. The *first* fragment id provided by the *kernel command line*
2. The *first* fragment id provided by the *device-tree*

Thus, this allows the device tree to provide a "default" for a location which
may be overridden by the kernel command line.

## Fragment Application Timing

Once this module is loaded, fragments are immediately applied.

Fragments are applied in the order that they are numbered in the
`dt-fragments` node. e.g. `fragment@0` is applied before `fragment@1`.

Operations are also applied in the same order via their numbering within their
fragment. e.g. `override@0` is applied before `override@1`.

Operations within fragments are continuously applied as they are parsed. Which
means that the init of drivers for moved nodes may occur before fragment-loader
is complete.


# Writing Fragments

Fragment nodes are to be added to `/dt-fragments`.

## Fragment Nodes

Fragments define a set of device tree modifications, and the "fragment id"
that activates them.

**Fragment node Property List**
- *[node reg]* - The reg value is used to define the order of which fragments
  should be applied.
- *[child nodes]* - All children of a fragment should be **operation nodes**.
- `location` - An arbitrary enumeration of a physical hardware location in a
  system.
- `compat` - An arbitrary enumeration of compatible hardware that could be
  present at a physical location.
- `param` - An arbitrary string for "fragment id" params that does **not**
  rely on `location` or `compat` enumerations.

## Operation Nodes

Operation nodes are the child nodes under a fragment that define the
device-tree modifications to perform.

All operations are described in detail under sub-headings below.

**Generic Operation Node Property List**
- *[node name]* - The name of the node defines the type of operation to apply.
- *[node reg]* - The reg value is used to define the order of which operations
  should be applied while applying a fragment.

### The `override` Operation Node

The `override` operation provides the ability to copy and overwrite device-tree
properties, and to **move** new child nodes.

Child nodes are moved to allow them to keep the same phandle without creating
duplicate phandles. This means they are removed from the out-of-tree fragment
when applied.

Further, child nodes can **not** overwrite an existing node. Attempting to do
so will result in an error from fragment-loader. Modifying existing nodes
should be done via modifying properties with seperate `override` operations.

**`Override` Node Property List**
- *[node name]* - Must be `override@N`
- `target` - A phandle reference of the in tree device-tree node to modify.
- `_overlay_` (child node) - The out-of-tree properties/nodes that are to be
  copied/moved into the "target" respectively.

## Example `/dt-fragment` Node

```C
/{
  dt-fragments {
    status = "okay";
    active-fragments = "l0_c4";

    fragment-component-name@0 {
      location = <0>;
      compat = <4>;
      param = "a_second_custom_enable_str";

      override@0 {
        target = <&target_node>;

        _overlay_ {
          status = "okay";
          arbitrary-prop = <23>;
          arbitrary-child-node@0 {
            status = "disabled";
          };
        };
      };
    };
  };
};
```
