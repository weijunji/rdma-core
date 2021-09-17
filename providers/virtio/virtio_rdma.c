/*
 * Copyright (c) 2021 Bytedance Inc. All rights reserved.
 *
 * Authors: Junji Wei <weijunji@bytedance.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <config.h>

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <errno.h>

#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#include "virtio_rdma.h"
#include "virtio_rdma_abi.h"
#include "virtio.h"

static void virtio_rdma_free_context(struct ibv_context *ibctx);

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_VIRTIO),
	VERBS_NAME_MATCH("virtio_rdma", NULL),
	{},
};

static int virtio_rdma_query_device(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp,
				       &resp_size);
	if (ret)
		return ret;

	raw_fw_ver = resp.base.fw_ver;
	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver),
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

static int virtio_rdma_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

static struct ibv_pd *virtio_rdma_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof(cmd),
					&resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	return pd;
}

static int virtio_rdma_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (!ret)
		free(pd);

	return ret;
}

static struct ibv_mr *virtio_rdma_reg_mr(struct ibv_pd *pd, void *addr,
                                         size_t length, uint64_t hca_va,
										 int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

static int virtio_rdma_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

static struct ibv_cq* virtio_rdma_create_cq (struct ibv_context *ctx,
											 int num_cqe,
					    			  		 struct ibv_comp_channel *channel,
					     			  		 int comp_vector)
{
	struct virtio_rdma_cq *cq;
	struct uvirtio_rdma_create_cq_resp resp;
	int rc;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	rc = ibv_cmd_create_cq(ctx, num_cqe, channel, comp_vector, &cq->ibv_cq.cq,
			       NULL, 0, &resp.ibv_resp, sizeof(resp));
	if (rc) {
		printf("cq creation failed: %d\n", rc);
		free(cq);
		return NULL;
	}

	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	cq->num_cqe = resp.num_cqe;

	cq->queue_size = resp.num_cqe * sizeof(*cq->queue);

	cq->queue = mmap(NULL, cq->queue_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->cmd_fd, resp.offset);

	printf("debug cq %s\n", (char*)cq->queue);

	if (cq->queue == MAP_FAILED) {
		printf("CQ mapping failed: %d", errno);
		goto fail;
	}

	return &cq->ibv_cq.cq;

fail:
	ibv_cmd_destroy_cq(&cq->ibv_cq.cq);
	free(cq);

	return NULL;
}

static int virtio_rdma_poll_cq (struct ibv_cq *cq, int num_entries,
								struct ibv_wc *wc)
{
	return 0;
}

static int virtio_rdma_destroy_cq (struct ibv_cq *ibcq)
{
	struct virtio_rdma_cq *cq = to_vcq(ibcq);
	int rc;

	rc = ibv_cmd_destroy_cq(ibcq);
	if (rc)
		return rc;

	if (cq->queue_size)
		munmap(cq->queue, cq->queue_size);
	free(cq);

	return 0;
}

static struct ibv_qp* virtio_rdma_create_qp (struct ibv_pd *pd,
									  		 struct ibv_qp_init_attr *attr)
{
	struct virtio_rdma_qp *qp;
	struct uvirtio_rdma_create_qp cmd;
	struct uvirtio_rdma_create_qp_resp resp;
	int rc;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
	
	qp->send_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	qp->recv_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	cmd.send_eventfd = qp->send_efd;
	cmd.recv_eventfd = qp->recv_efd;

	rc = ibv_cmd_create_qp(pd, &qp->ibv_qp.qp, attr,
			       &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (rc) {
		printf("qp creation failed: %d\n", rc);
		free(qp);
		return NULL;
	}

	qp->sq.addr = mmap(NULL, resp.sq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, pd->context->cmd_fd, resp.sq_offset);
	if (qp->sq.addr == MAP_FAILED) {
		printf("QP mapping failed: %d\n", errno);
		goto fail;
	}

	qp->sq.doorbell = qp->sq.addr;
	qp->sq.index = resp.sq_idx;
	*(__u16*)qp->sq.doorbell = htole16(qp->sq.index);

	qp->rq.addr = mmap(NULL, resp.rq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, pd->context->cmd_fd, resp.rq_offset);
	if (qp->rq.addr == MAP_FAILED) {
		printf("QP mapping failed: %d\n", errno);
		goto fail;
	}

	qp->rq.doorbell = qp->rq.addr;
	qp->rq.index = resp.rq_idx;
	*(__u16*)qp->rq.doorbell = htole16(qp->rq.index);
/*	
	int getpagesize(void);
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	cq->num_cqe = resp.num_cqe;

	cq->queue_size = resp.num_cqe * sizeof(*cq->queue);

	cq->queue = mmap(NULL, cq->queue_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->cmd_fd, resp.offset);

	printf("debug cq %s\n", (char*)cq->queue);

	if (cq->queue == MAP_FAILED) {
		printf("CQ mapping failed: %d", errno);
		goto fail;
	}
*/
	return &qp->ibv_qp.qp;

fail:
	ibv_cmd_destroy_qp(&qp->ibv_qp.qp);
	free(qp);

	return NULL;
}

static struct ibv_qp* virtio_rdma_create_qp_ex (struct ibv_context *context,
			struct ibv_qp_init_attr_ex *qp_init_attr_ex)
{
	return NULL;
}

static int virtio_rdma_query_qp (struct ibv_qp *qp, struct ibv_qp_attr *attr,
			              		 int attr_mask,
								 struct ibv_qp_init_attr *init_attr)
{
	return 0;
}

static int virtio_rdma_modify_qp (struct ibv_qp *qp, struct ibv_qp_attr *attr,
			               		  int attr_mask)
{
	return 0;
}

static int virtio_rdma_destroy_qp (struct ibv_qp *qp)
{
	return 0;
}

static int	virtio_rdma_post_send (struct ibv_qp *qp, struct ibv_send_wr *wr,
			               		   struct ibv_send_wr **bad_wr)
{
	return 0;
}

static int	virtio_rdma_post_recv (struct ibv_qp *qp, struct ibv_recv_wr *wr,
			 			   		   struct ibv_recv_wr **bad_wr)
{
	return 0;
}

static const struct verbs_context_ops virtio_rdma_ctx_ops = {
	.query_device_ex = virtio_rdma_query_device,
	.query_port = virtio_rdma_query_port,
	.alloc_pd = virtio_rdma_alloc_pd,
	.dealloc_pd = virtio_rdma_dealloc_pd,
	.reg_mr = virtio_rdma_reg_mr,
	.dereg_mr = virtio_rdma_dereg_mr,
	.create_cq = virtio_rdma_create_cq,
	.poll_cq = virtio_rdma_poll_cq,
	.destroy_cq = virtio_rdma_destroy_cq,
	// .create_srq = virtio_rdma_create_srq,
	// .modify_srq = virtio_rdma_modify_srq,
	// .query_srq = virtio_rdma_query_srq,
	// .destroy_srq = virtio_rdma_destroy_srq,
	// .post_srq_recv = virtio_rdma_post_srq_recv,
	.create_qp = virtio_rdma_create_qp,
	.create_qp_ex = virtio_rdma_create_qp_ex,
	.query_qp = virtio_rdma_query_qp,
	.modify_qp = virtio_rdma_modify_qp,
	.destroy_qp = virtio_rdma_destroy_qp,
	.post_send = virtio_rdma_post_send,
	.post_recv = virtio_rdma_post_recv,
	// .create_ah = virtio_rdma_create_ah,
	// .destroy_ah = virtio_rdma_destroy_ah,
	// .attach_mcast = ibv_cmd_attach_mcast,
	// .detach_mcast = ibv_cmd_detach_mcast,
	.free_context = virtio_rdma_free_context,
};

static struct verbs_context *virtio_rdma_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd,
					       void *private_data)
{
	struct virtio_rdma_context *context;
	struct ibv_get_context cmd;
	struct ib_uverbs_get_context_resp resp;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_VIRTIO);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp, sizeof(resp)))
		goto out;

	verbs_set_ops(&context->ibv_ctx, &virtio_rdma_ctx_ops);

	return &context->ibv_ctx;

out:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void virtio_rdma_free_context(struct ibv_context *ibctx)
{
	struct virtio_rdma_context *context = to_vctx(ibctx);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static struct verbs_device *virtio_rdma_device_alloc(struct verbs_sysfs_dev *unused)
{
	struct virtio_rdma_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static void virtio_rdma_device_free(struct verbs_device *verbs_dev) {
	struct virtio_rdma_device *vdev = to_vdev(&verbs_dev->device);
	free(vdev);
}

static const struct verbs_device_ops virtio_rdma_dev_ops = {
	.name = "virtio_rdma",
	/*
	 * For 64 bit machines ABI version 1 and 2 are the same. Otherwise 32
	 * bit machines require ABI version 2 which guarentees the user and
	 * kernel use the same ABI.
	 */
	.match_min_abi_version = VIRTIO_RDMA_ABI_VERSION,
	.match_max_abi_version = VIRTIO_RDMA_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = virtio_rdma_device_alloc,
	.uninit_device = virtio_rdma_device_free,
	.alloc_context = virtio_rdma_alloc_context,
};
PROVIDER_DRIVER(virtio_rdma, virtio_rdma_dev_ops);
