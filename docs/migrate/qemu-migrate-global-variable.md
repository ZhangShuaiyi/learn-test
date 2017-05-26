1. savevm_state
2. ram_list
3. migration_bitmap_rcu
4. migration_dirty_pages
qemu动态迁移的几个全局变量

## 1. savevm_state
声明在migration/savevm.c中
```c
static SaveState savevm_state = {
    .handlers = QTAILQ_HEAD_INITIALIZER(savevm_state.handlers),
    .global_section_id = 0,
    .skip_configuration = false,
};
```
数据结构中有SaveStateEntry的链表handlers，在虚拟机启动的初始化阶段会调用register_savevm_live和vmstate_register_with_alias_id函数，进而调用QTAILQ_INSERT_TAIL(&savevm_state.handlers, se, entry);其中section_id是递增的。
```c
se = g_new0(SaveStateEntry, 1);
se->version_id = version_id;
se->section_id = savevm_state.global_section_id++;
se->ops = ops;
se->opaque = opaque;
```

## 2. ram_list

### 2.1 ram_list.blocks
```c
struct RAMBlock {
    ...
    ram_addr_t offset;  # 该内存区域在整个内存中的偏移
    ram_addr_t used_length; # 该内存区域的当前大小
    ram_addr_t max_length;  # 该内存区域的最大大小
    ...
}
```
ram_list.blocks为RAMBlock类型的链表，链表的插入操作在 **ram_block_add** 中进行
```
qemu_ram_alloc_internal
-->ram_block_add
```
使用 **qemu_ram_set_idstr** 通过查找RAMBlock的offset设置idstr
```c
vmstate_register_ram
-->qemu_ram_set_idstr
   -->find_ram_block
```

### 2.2 ram_list.dirty_memory
```c
typedef struct RAMList {
    ...
    DirtyMemoryBlocks *dirty_memory[DIRTY_MEMORY_NUM];
    ...
} RAMList;
typedef struct {
    struct rcu_head rcu;
    unsigned long *blocks[];
} DirtyMemoryBlocks;
```
