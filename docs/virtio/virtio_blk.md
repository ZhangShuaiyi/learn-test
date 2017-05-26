## 1. virtio_blk设备probe和remove

### 1.1 virtblk_probe
virtio_blk设备名称为/dev/vdX
+ ida_simple_get(&vd_index_ida, ...)获取索引index
+ virtblk_name_format("vd", index, vblk->disk->disk_name, DISK_NAME_LEN); 根据索引index设置disk->disk_name为/dev/vdX
+ add_disk(vblk->disk); 添加disk

### 1.2 virtblk_remove
+ refc = atomic_read(&disk_to_dev(vblk->disk)->kobj.kref.refcount);
+ 在refc==1时执行ida_simple_remove(&vd_index_ida, index);减少vd_index_ida中的索引
