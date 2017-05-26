虚拟机动态迁移内存bitmap相关变量和函数

## 1. bitmap数据类型和变量
```c
static struct BitmapRcu {
    struct rcu_head rcu;
    /* Main migration bitmap */
    unsigned long *bmap;
    /* bitmap of pages that haven't been sent even once
     * only maintained and used in postcopy at the moment
     * where it's used to send the dirtymap at the start
     * of the postcopy phase
     */
    unsigned long *unsentmap;
} *migration_bitmap_rcu;
```
+ 静态全局变量migration_bitmap_rcu
+ bmap为unsigned long指针

## 2. bitmap相关函数

### 2.1 bitmap_new
通过g_try_malloc0申请内存空间保存内存位图信息，内存位图每bit位代表一个内存页，bitmap_new传入的内存页数目对应bitmap的bit数目，最终申请内存空间大小为ceil(ram_bitmap_pages/64)*8

### 2.2 bitmap_set
```c
void bitmap_set(unsigned long *map, long start, long nr)
```
将bitmap中起始为start，长度为nr的bit置为1

### 2.3 migration_bitmap_sync
```c
migration_bitmap_sync
-->address_space_sync_dirty_bitmap
   -->kvm_log_sync
      -->kvm_physical_sync_dirty_bitmap
         -->kvm_vm_ioctl(s, KVM_GET_DIRTY_LOG, &d)
         -->kvm_get_dirty_pages_log_range
            -->cpu_physical_memory_set_dirty_lebitmap  ## 更新ram_list.dirty_memory
-->migration_bitmap_sync_range
```

#### 2.3.1 address_space_sync_dirty_bitmap
address_space_sync_dirty_bitmap调用kvm_log_sync获取kvm中内存脏页信息。

### 2.4 ram_find_and_save_block
```c
ram_find_and_save_block
-->find_dirty_block
   -->migration_bitmap_find_dirty
-->ram_save_host_page
   -->ram_save_host_page
      -->ram_save_target_page
         -->migration_bitmap_clear_dirty
            -->test_and_clear_bit  ## 清空bitmap的制定bit位返回旧值，migration_dirty_pages--
         -->ram_save_page
```

#### 2.4.1 find_dirty_block

