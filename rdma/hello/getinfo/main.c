#include <stdio.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

int main(int argc, char *argv[]) {
    struct ibv_device **devs;
    int num_devs;

    devs = ibv_get_device_list(&num_devs);
    if (devs == NULL || num_devs == 0) {
        printf("No rdma device found!\n");
        return EXIT_FAILURE;
    }
    printf("Total rdma devices:%d\n", num_devs);

    for (int i=0; i<num_devs; i++) {
        printf("----- RDMA device %d -----\n", i);
        const char *name = ibv_get_device_name(devs[i]);
        if (name == NULL) {
            printf("ibv_get_device_name failed\n");
            return EXIT_FAILURE;
        }
        printf("name\t: %s\n", name);

        struct ibv_context *ctx = ibv_open_device(devs[i]);
        if (ctx == NULL) {
            printf("ibv_open_device failed\n");
            return EXIT_FAILURE;
        }

        struct ibv_device_attr attr;
        int ret = ibv_query_device(ctx, &attr);
        if (ret != 0) {
            printf("ibv_query_device failed\n");
            return EXIT_FAILURE;
        }
        printf("fw_ver\t: %s\n"
                "max_qp\t: %d\n",
                attr.fw_ver,
                attr.max_qp);
        ibv_close_device(ctx);
    }
    return EXIT_SUCCESS;
}
