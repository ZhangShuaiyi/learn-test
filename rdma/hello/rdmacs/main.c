#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <infiniband/verbs.h>

static int is_roce = 1;

#define IB_PORT     1
#define MSG_SIZE    64

#define CHECK(c, fmt, ...)                                               \
    do                                                                   \
    {                                                                    \
        if (!(c))                                                        \
        {                                                                \
            printf("%s:%d, %s, errno=%d, %s\n", __FILE__, __LINE__, fmt, \
                   ##__VA_ARGS__, errno, strerror(errno));               \
            exit(EXIT_FAILURE);                                                    \
        }                                                                \
    } while (0)

enum ibv_qp_state get_qp_state(struct ibv_qp *qp) {
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;
    int ret = ibv_query_qp(qp, &attr, IBV_QP_STATE, &init_attr);
    CHECK(ret == 0, "ibv_query_qp failed in get_qp_state");
    return attr.qp_state;
}

const char *stat_to_str(enum ibv_qp_state s) {
    switch (s)
    {
    case IBV_QPS_RESET:
        return "IBV_QPS_RESET";
    case IBV_QPS_INIT:
        return "IBV_QPS_INIT";
    case IBV_QPS_RTR:
        return "IBV_QPS_RTR";
    case IBV_QPS_RTS:
        return "IBV_QPS_RTS";
    case IBV_QPS_SQD:
        return "IBV_QPS_SQD";
    case IBV_QPS_SQE:
        return "IBV_QPS_SQE";
    case IBV_QPS_ERR:
        return "IBV_QPS_ERR";
    case IBV_QPS_UNKNOWN:
        return "IBV_QPS_UNKNOWN";
    default:
        return "UNKNOWN";
    }
}

int modify_qp_to_rts (struct ibv_qp *qp, uint32_t target_qp_num, uint16_t target_lid, union ibv_gid gid) {
    int ret = 0;
    // change QP state to INIT
    {
	struct ibv_qp_attr qp_attr = {
	    .qp_state        = IBV_QPS_INIT,
	    .pkey_index      = 0,
	    .port_num        = IB_PORT,
	    .qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
	                       IBV_ACCESS_REMOTE_READ |
	                       IBV_ACCESS_REMOTE_ATOMIC |
	                       IBV_ACCESS_REMOTE_WRITE,
	};

	ret = ibv_modify_qp (qp, &qp_attr,
			 IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			 IBV_QP_PORT  | IBV_QP_ACCESS_FLAGS);
	CHECK(ret == 0, "Failed to modify qp to INIT.");
    printf("qp current state is: %s\n", stat_to_str(get_qp_state(qp)));
    }

    // Change QP state to RTR
    {
    struct ibv_qp_attr  qp_attr = {
	    .qp_state           = IBV_QPS_RTR,
	    .path_mtu           = IBV_MTU_1024,
	    .dest_qp_num        = target_qp_num,
	    .rq_psn             = 0,
	    .max_dest_rd_atomic = 1,
	    .min_rnr_timer      = 12,
	    // .ah_attr.is_global  = 0,
        .ah_attr.is_global  = 1,
        .ah_attr.grh.hop_limit  = 1,
        .ah_attr.grh.sgid_index = 1,
        .ah_attr.grh.dgid   = gid,
	    .ah_attr.dlid       = target_lid,
	    .ah_attr.sl         = 0,
	    .ah_attr.src_path_bits = 0,
	    .ah_attr.port_num      = IB_PORT,
	};

    // if (is_roce == 1) {
    //     qp_attr.ah_attr.is_global = 1;
    //     qp_attr.ah_attr.grh.hop_limit = 0xFF;
    //     qp_attr.ah_attr.grh.dgid = gid;
    //     qp_attr.ah_attr.grh.sgid_index = 1;
    // } else {
    //     qp_attr.ah_attr.is_global = 0;
    //     // qp_attr.ah_attr.dlid = target_lid;
    // }

	ret = ibv_modify_qp(qp, &qp_attr,
			    IBV_QP_STATE | IBV_QP_AV |
			    IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
			    IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC |
			    IBV_QP_MIN_RNR_TIMER);
    CHECK(ret == 0, "Failed to modify qp to RTR.");
    printf("qp current state is: %s\n", stat_to_str(get_qp_state(qp)));
    }

    // Change QP state to RTS
    {
    struct ibv_qp_attr  qp_attr = {
	    .qp_state      = IBV_QPS_RTS,
	    .timeout       = 14,
	    .retry_cnt     = 7,
	    .rnr_retry     = 7,
	    .sq_psn        = 0,
	    .max_rd_atomic = 1,
	};

	ret = ibv_modify_qp (qp, &qp_attr,
			     IBV_QP_STATE | IBV_QP_TIMEOUT |
			     IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
			     IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
    CHECK(ret == 0, "Failed to modify qp to RTS.");
    printf("qp current state is: %s\n", stat_to_str(get_qp_state(qp)));
    }
    return 0;
}

int run_server(struct ibv_qp *qp, uint32_t qp_num, uint16_t lid, union ibv_gid gid) {
    uint16_t remote_lid;
    uint32_t remote_qp_num;
    union ibv_gid remote_gid;
    printf("Wait to input remote qp_num and lid\n");
    fscanf(stdin, "%d %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", &remote_qp_num, &remote_lid,
            &remote_gid.raw[0], &remote_gid.raw[1], &remote_gid.raw[2], &remote_gid.raw[3],
            &remote_gid.raw[4], &remote_gid.raw[5], &remote_gid.raw[6], &remote_gid.raw[7],
            &remote_gid.raw[8], &remote_gid.raw[9], &remote_gid.raw[10], &remote_gid.raw[11],
            &remote_gid.raw[12], &remote_gid.raw[13], &remote_gid.raw[14], &remote_gid.raw[15]);
    printf("%d %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", qp_num, lid, 
            gid.raw[0], gid.raw[1], gid.raw[2], gid.raw[3],
            gid.raw[4], gid.raw[5], gid.raw[6], gid.raw[7],
            gid.raw[8], gid.raw[9], gid.raw[10], gid.raw[11],
            gid.raw[12], gid.raw[13], gid.raw[14], gid.raw[15]);
    modify_qp_to_rts(qp, remote_qp_num, remote_lid, remote_gid);
    return 0;
}

int run_client(struct ibv_qp *qp, uint32_t qp_num, uint16_t lid, union ibv_gid gid) {
    uint16_t remote_lid;
    uint32_t remote_qp_num;
    union ibv_gid remote_gid;
    printf("%d %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", qp_num, lid, 
            gid.raw[0], gid.raw[1], gid.raw[2], gid.raw[3],
            gid.raw[4], gid.raw[5], gid.raw[6], gid.raw[7],
            gid.raw[8], gid.raw[9], gid.raw[10], gid.raw[11],
            gid.raw[12], gid.raw[13], gid.raw[14], gid.raw[15]);
    printf("Wait to input remote qp_num and lid\n");
    fscanf(stdin, "%d %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", &remote_qp_num, &remote_lid,
            &remote_gid.raw[0], &remote_gid.raw[1], &remote_gid.raw[2], &remote_gid.raw[3],
            &remote_gid.raw[4], &remote_gid.raw[5], &remote_gid.raw[6], &remote_gid.raw[7],
            &remote_gid.raw[8], &remote_gid.raw[9], &remote_gid.raw[10], &remote_gid.raw[11],
            &remote_gid.raw[12], &remote_gid.raw[13], &remote_gid.raw[14], &remote_gid.raw[15]);
    // printf("%d %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", qp_num, lid, 
    //         remote_gid.raw[0], remote_gid.raw[1], remote_gid.raw[2], remote_gid.raw[3],
    //         remote_gid.raw[4], remote_gid.raw[5], remote_gid.raw[6], remote_gid.raw[7],
    //         remote_gid.raw[8], remote_gid.raw[9], remote_gid.raw[10], remote_gid.raw[11],
    //         remote_gid.raw[12], remote_gid.raw[13], remote_gid.raw[14], remote_gid.raw[15]);
    modify_qp_to_rts(qp, remote_qp_num, remote_lid, remote_gid);
    return 0;
}

int main(int argc, char *argv[]) {
    struct ibv_device **devs;
    int num_devs, ret;

    devs = ibv_get_device_list(&num_devs);
    CHECK(devs != NULL, "ibv_get_device_list failed");
    printf("num devices:%d\n", num_devs);

    // Get IB context
    struct ibv_context *ctx = ibv_open_device(devs[0]);
    CHECK(ctx != NULL, "ibv_open_device failed");
    // Allocate IB protection domain
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    CHECK(pd != NULL, "ibv_alloc_pd failed");
    // Register IB memory region
    size_t ib_buf_size = MSG_SIZE * 1;
    char *ib_buf = (char *) memalign (4096, ib_buf_size);
    CHECK(ib_buf != NULL, "memalign failed");
    struct ibv_mr *mr = ibv_reg_mr(pd, ib_buf, ib_buf_size,
                        IBV_ACCESS_LOCAL_WRITE | 
                        IBV_ACCESS_REMOTE_READ | 
                        IBV_ACCESS_REMOTE_WRITE);
    CHECK(mr != NULL, "ibv_reg_mr failed");
    // Create Completion Queue
    struct ibv_device_attr dev_attr;
    ret = ibv_query_device(ctx, &dev_attr);
    CHECK(ret == 0, "ibv_query_device failed");
    struct ibv_cq *cq = ibv_create_cq(ctx, dev_attr.max_cqe, NULL, NULL, 0);
    CHECK(cq != NULL, "ibv_create_cq failed");
    // Create Queue Pair
    // https://www.rdmamojo.com/2012/12/21/ibv_create_qp/
    struct ibv_qp_init_attr qp_init_attr = {
        .send_cq = cq,
        .recv_cq = cq,
        .cap = {
            .max_send_wr = dev_attr.max_qp_wr,
            .max_recv_wr = dev_attr.max_qp_wr,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
        .qp_type = IBV_QPT_RC,
    };
    struct ibv_qp *qp = ibv_create_qp(pd, &qp_init_attr);
    CHECK(qp != NULL, "ibv_create_qp failed");
    printf("qp current state is: %s\n", stat_to_str(get_qp_state(qp)));
    // Query IB port attribute
    struct ibv_port_attr port_attr;
    ret = ibv_query_port(ctx, IB_PORT, &port_attr);
    CHECK(ret == 0, "ibv_query_port failed");
    // Get gid (roce need gid)
    union ibv_gid gid;
    ret = ibv_query_gid(ctx, IB_PORT, 1, &gid);
    CHECK(ret == 0, "ibv_query_gid fail");
    // printf("device port info: qp_num=%d lid=%d\n", qp->qp_num, port_attr.lid);
    // Connect QP
    if (argc < 2) {
        run_server(qp, qp->qp_num, port_attr.lid, gid);
    } else {
        run_client(qp, qp->qp_num, port_attr.lid, gid);
    }


    ibv_close_device(ctx);
    return 0;
}
