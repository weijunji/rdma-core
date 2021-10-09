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
#include <errno.h>
#include <stddef.h>

#include <linux/virtio_ring.h>

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
	struct uvirtio_rdma_alloc_pd_resp resp;
	struct virtio_rdma_pd *pd;

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof(cmd),
					&resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	pd->pdn = resp.pdn;
printf("DEBUG pdn %u", pd->pdn);
	return &pd->ibv_pd;
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
	struct virtio_rdma_buf_pool_entry *buf_entry;
	int rc, i;

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

	cq->vring.buf = mmap(NULL, resp.cq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->cmd_fd, resp.offset);
	if (cq->vring.buf == MAP_FAILED) {
		printf("CQ mapping failed: %d", errno);
		goto fail;
	}

	cq->vring.buf_size = resp.cq_size;
	cq->vring.kbuf = cq->vring.buf + resp.vq_size;
	cq->vring.kbuf_addr = resp.cq_phys_addr;
	cq->vring.kbuf_len = resp.cq_size - resp.vq_size;

	vring_init(&cq->vring.ring, resp.num_cvqe, cq->vring.buf, resp.vq_align);
	if (vring_init_pool(&cq->vring, cq->num_cqe, sizeof(struct virtio_rdma_cqe), true)) {
		munmap(cq->vring.buf, cq->vring.buf_size);
		goto fail;
	}

	for (i = 0; i < cq->num_cqe; i++) {
		buf_entry = vring_flist_pop(&cq->vring);
		vring_add_one(&cq->vring, buf_entry, sizeof(struct virtio_rdma_cqe));
	}

	printf("debug cq %s\n", (char*)cq->vring.kbuf);
	printf("num_cqe %u %u\n", cq->num_cqe, resp.num_cvqe);
	// FIXME: need reset virtqueue
	// cq->vring.last_used_idx = 512;

	return &cq->ibv_cq.cq;

fail:
	ibv_cmd_destroy_cq(&cq->ibv_cq.cq);
	free(cq);

	return NULL;
}

static int virtio_rdma_poll_cq (struct ibv_cq *ibcq, int num_entries,
								struct ibv_wc *wc)
{
	struct virtio_rdma_cq *cq = to_vcq(ibcq);
	struct virtio_rdma_buf_pool_entry* buf_entry;
	struct virtio_rdma_cqe *cqe;
	int i = 0;

	pthread_spin_lock(&cq->lock);
	while (i < num_entries) {
		buf_entry = vring_get_one(&cq->vring);
		if (!buf_entry)
			break;

		cqe = buf_entry->buf;
		wc[i].wr_id = cqe->wr_id;
		wc[i].status = cqe->status;
		wc[i].opcode = cqe->opcode;
		wc[i].vendor_err = cqe->vendor_err;
		wc[i].byte_len = cqe->byte_len;
		// TODO: wc[i].qp_num
		wc[i].imm_data = cqe->ex.imm_data;
		wc[i].src_qp = cqe->src_qp;
		wc[i].slid = cqe->slid;
		wc[i].wc_flags = cqe->wc_flags;
		wc[i].pkey_index = cqe->pkey_index;
		wc[i].sl = cqe->sl;
		wc[i].dlid_path_bits = cqe->dlid_path_bits;
		// printf("got cqe %lu\n", wc[i].wr_id);
		vring_add_one(&cq->vring, buf_entry, buf_entry->len);
		i++;
	}
	pthread_spin_unlock(&cq->lock);
	return i;
}

static int virtio_rdma_destroy_cq (struct ibv_cq *ibcq)
{
	struct virtio_rdma_cq *cq = to_vcq(ibcq);
	int rc;

	rc = ibv_cmd_destroy_cq(ibcq);
	if (rc)
		return rc;

	if (cq->vring.buf)
		munmap(cq->vring.buf, cq->vring.buf_size);
	free(cq->vring.pool_table);
	free(cq);
	return 0;
}

static struct ibv_qp* virtio_rdma_create_qp (struct ibv_pd *pd,
									  		 struct ibv_qp_init_attr *attr)
{
	struct virtio_rdma_qp *qp;
	struct uvirtio_rdma_create_qp_resp resp;
	int rc;
	__u32 page_size;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
printf("qp size: %d %d\n", attr->cap.max_send_wr, attr->cap.max_recv_wr);
	rc = ibv_cmd_create_qp(pd, &qp->ibv_qp.qp, attr,
			       NULL, 0, &resp.ibv_resp, sizeof(resp));
	if (rc) {
		printf("qp creation failed: %d\n", rc);
		free(qp);
		return NULL;
	}

	page_size = resp.page_size;

	pthread_spin_init(&qp->slock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rlock, PTHREAD_PROCESS_PRIVATE);
	qp->num_sqe = resp.num_sqe;
	qp->num_rqe = resp.num_rqe;
	qp->num_sq_sge = attr->cap.max_send_sge;
	qp->num_rq_sge = attr->cap.max_recv_sge;
	qp->qpn = resp.qpn;

	qp->sq.buf = mmap(NULL, resp.sq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, pd->context->cmd_fd, resp.sq_offset);
	if (qp->sq.buf == MAP_FAILED) {
		printf("QP mapping failed: %d\n", errno);
		goto fail;
	}

	qp->sq.doorbell = qp->sq.buf;
	qp->sq.index = resp.sq_idx;
	qp->sq.buf_size = resp.sq_size;
	qp->sq.kbuf = qp->sq.buf + page_size + resp.svq_size;
	qp->sq.kbuf_addr = resp.sq_phys_addr;
	qp->sq.kbuf_len = resp.sq_size - page_size - resp.svq_size;
	vring_init(&qp->sq.ring, resp.num_svqe, qp->sq.buf + page_size, resp.vq_align);
	if (vring_init_pool(&qp->sq, qp->num_sqe,
		sizeof(struct virtio_rdma_cmd_post_send) + qp->num_sq_sge *
		sizeof(struct virtio_rdma_sge), false))
		goto fail_sq;

	qp->rq.buf = mmap(NULL, resp.rq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, pd->context->cmd_fd, resp.rq_offset);
	if (qp->rq.buf == MAP_FAILED) {
		printf("QP mapping failed: %d\n", errno);
		goto fail_sq;
	}

	qp->rq.doorbell = qp->rq.buf;
	qp->rq.index = resp.rq_idx;
	qp->rq.buf_size = resp.rq_size;
	qp->rq.kbuf = qp->rq.buf + page_size + resp.rvq_size;
	qp->rq.kbuf_addr = resp.rq_phys_addr;
	qp->rq.kbuf_len = resp.rq_size - page_size - resp.rvq_size;
	vring_init(&qp->rq.ring, resp.num_rvqe, qp->rq.buf + page_size, resp.vq_align);
	if (vring_init_pool(&qp->rq, qp->num_rqe,
		sizeof(struct virtio_rdma_cmd_post_recv) + qp->num_rq_sge *
		sizeof(struct virtio_rdma_sge), false))
		goto fail_rq;

	// DEBUG
	vring_notify(&qp->sq);
	vring_notify(&qp->rq);
	printf("debug sq %s %u %u\n", (char*)qp->sq.kbuf, qp->sq.index, qp->qpn);
	printf("debug rq %s %u\n", (char*)qp->rq.kbuf, qp->rq.index);

	return &qp->ibv_qp.qp;

fail_rq:
	munmap(qp->rq.buf, qp->rq.buf_size);
fail_sq:
	munmap(qp->sq.buf, qp->sq.buf_size);
fail:
	ibv_cmd_destroy_qp(&qp->ibv_qp.qp);
	free(qp);

	return NULL;
}

static int virtio_rdma_query_qp (struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			              		 int attr_mask,
								 struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd = {};

	return ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr,
				&cmd, sizeof(cmd));
}

static int virtio_rdma_modify_qp (struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			               		  int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
}

static int virtio_rdma_destroy_qp (struct ibv_qp *ibqp)
{
	struct virtio_rdma_qp *qp = to_vqp(ibqp);
	int rc;

	rc = ibv_cmd_destroy_qp(ibqp);
	if (rc)
		return rc;

	if (qp->sq.buf)
		munmap(qp->sq.buf, qp->sq.buf_size);
	if (qp->rq.buf)
		munmap(qp->rq.buf, qp->rq.buf_size);
	free(qp->sq.pool_table);
	free(qp->rq.pool_table);
	free(qp);
	return 0;
}

static int	virtio_rdma_post_send (struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			               		   struct ibv_send_wr **bad_wr)
{
	struct virtio_rdma_qp* qp = to_vqp(ibqp);
	struct virtio_rdma_buf_pool_entry* buf_entry;
	struct virtio_rdma_cmd_post_send *cmd;
	struct virtio_rdma_sge *sgl;
	uint32_t sgl_len;
	int rc = 0;
	//printf("post_send\n");
	pthread_spin_lock(&qp->slock);
	while (wr) {
		while ((buf_entry = vring_get_one(&qp->sq)) != NULL) {
			//printf("Got one in sq\n");
			vring_flist_push(&qp->sq, buf_entry);
		}

		// TODO: more check
		buf_entry = vring_flist_pop(&qp->sq);
		if (!buf_entry) {
			rc = -ENOMEM;
			printf("error\n");
			goto out_err;
		}

		cmd = buf_entry->buf;
		sgl = buf_entry->buf + sizeof(*cmd);
		sgl_len = sizeof(*sgl) * wr->num_sge;

		cmd->qpn = qp->qpn;
		cmd->is_kernel = 0;
		cmd->num_sge = wr->num_sge;
		cmd->send_flags = wr->send_flags;
		cmd->opcode = wr->opcode;
		cmd->wr_id = wr->wr_id;
		cmd->ex.imm_data = wr->imm_data;

		switch (ibqp->qp_type) {
		case IBV_QPT_UD:
			cmd->wr.ud.remote_qpn = wr->wr.ud.remote_qpn;
			cmd->wr.ud.remote_qkey = wr->wr.ud.remote_qkey;
			cmd->wr.ud.av = to_vah(wr->wr.ud.ah)->av;
			break;
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				cmd->wr.rdma.remote_addr = wr->wr.rdma.remote_addr;
				cmd->wr.rdma.rkey = wr->wr.rdma.rkey;
				break;
			case IBV_WR_LOCAL_INV:
			case IBV_WR_SEND_WITH_INV:
				cmd->ex.invalidate_rkey = wr->invalidate_rkey;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				cmd->wr.atomic.remote_addr = wr->wr.atomic.remote_addr;
				cmd->wr.atomic.rkey = wr->wr.atomic.rkey;
				cmd->wr.atomic.compare_add = wr->wr.atomic.compare_add;
				if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
					cmd->wr.atomic.swap = wr->wr.atomic.swap;
				break;
			default:
				break;
			}
			break;
		default:
			rc = -EINVAL;
			goto out_err;
		}
		memcpy(sgl, wr->sg_list, sgl_len);

		vring_add_one(&qp->sq, buf_entry, sizeof(*cmd) + sgl_len);

		wr = wr->next;
	}
	vring_notify(&qp->sq);

out_err:
	*bad_wr = wr;
	pthread_spin_unlock(&qp->slock);
	return rc;
}

static int	virtio_rdma_post_recv (struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			 			   		   struct ibv_recv_wr **bad_wr)
{
	struct virtio_rdma_qp* qp = to_vqp(ibqp);
	struct virtio_rdma_buf_pool_entry* buf_entry;
	struct virtio_rdma_cmd_post_recv *cmd;
	struct virtio_rdma_sge *sgl;
	uint32_t sgl_len;
	int rc = 0;
	// printf("post_recv\n");
	pthread_spin_lock(&qp->rlock);
	while (wr) {
		while ((buf_entry = vring_get_one(&qp->rq)) != NULL) {
			vring_flist_push(&qp->rq, buf_entry);
		}

		// TODO: more check
		buf_entry = vring_flist_pop(&qp->rq);
		if (!buf_entry) {
			*bad_wr = wr;
			rc = -ENOMEM;
			printf("error\n");
			goto out;
		}

		cmd = buf_entry->buf;
		sgl = buf_entry->buf + sizeof(*cmd);
		sgl_len = sizeof(*sgl) * wr->num_sge;

		cmd->qpn = qp->qpn;
		cmd->is_kernel = 0;
		cmd->num_sge = wr->num_sge;
		cmd->wr_id = wr->wr_id;
		memcpy(sgl, wr->sg_list, sgl_len);

		vring_add_one(&qp->rq, buf_entry, sizeof(*cmd) + sgl_len);

		wr = wr->next;
	}
	vring_notify(&qp->rq);

out:
	pthread_spin_unlock(&qp->rlock);
	return rc;
}

static int is_multicast_gid(const union ibv_gid *gid)
{
	return gid->raw[0] == 0xff;
}

static int is_link_local_gid(const union ibv_gid *gid)
{
	return gid->global.subnet_prefix == htobe64(0xfe80000000000000ULL);
}

static int is_ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(&a->s6_addr32) ||
		/* IPv4 encoded multicast addresses */
		(a->s6_addr32[0] == htobe32(0xff0e0000) &&
		((a->s6_addr32[1] |
		 (a->s6_addr32[2] ^ htobe32(0x0000ffff))) == 0UL));
}

static int set_mac_from_gid(const union ibv_gid *gid,
			     __u8 mac[6])
{
	if (is_link_local_gid(gid)) {
		/*
		 * The MAC is embedded in GID[8-10,13-15] with the
		 * 7th most significant bit inverted.
		 */
		memcpy(mac, gid->raw + 8, 3);
		memcpy(mac + 3, gid->raw + 13, 3);
		mac[0] ^= 2;

		return 0;
	}

	return 1;
}

static struct ibv_ah* virtio_rdma_create_ah(struct ibv_pd *pd,
				struct ibv_ah_attr *attr)
{
	struct virtio_rdma_ah *ah;
	struct virtio_rdma_av *av;
	struct ibv_port_attr port_attr;

	if (!attr->is_global)
		return NULL;

	if (ibv_query_port(pd->context, attr->port_num, &port_attr))
		return NULL;

	if (port_attr.link_layer == IBV_LINK_LAYER_UNSPECIFIED ||
	    port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND)
		return NULL;

	if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET &&
	    (!is_link_local_gid(&attr->grh.dgid) &&
	     !is_multicast_gid(&attr->grh.dgid)  &&
	     !is_ipv6_addr_v4mapped((struct in6_addr *)attr->grh.dgid.raw)))
		return NULL;

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	av = &ah->av;
	av->port = attr->port_num;
	av->pdn = to_vpd(pd)->pdn;
	av->src_path_bits = attr->src_path_bits;
	av->src_path_bits |= 0x80;
	av->gid_index = attr->grh.sgid_index;
	av->hop_limit = attr->grh.hop_limit;
	av->sl_tclass_flowlabel = (attr->grh.traffic_class << 20) |
				   attr->grh.flow_label;
	memcpy(av->dgid, attr->grh.dgid.raw, 16);

	if (port_attr.port_cap_flags & IBV_PORT_IP_BASED_GIDS) {
		if (!ibv_resolve_eth_l2_from_gid(pd->context, attr,
						 av->dmac, NULL))
			return &ah->ibv_ah;
	} else {
		if (!set_mac_from_gid(&attr->grh.dgid, av->dmac))
			return &ah->ibv_ah;
	}

	free(ah);
	return NULL;
}

static int virtio_rdma_destroy_ah(struct ibv_ah *ah)
{
	free(to_vah(ah));
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
	.req_notify_cq = ibv_cmd_req_notify_cq,
	.destroy_cq = virtio_rdma_destroy_cq,

	// .create_srq = virtio_rdma_create_srq,
	// .modify_srq = virtio_rdma_modify_srq,
	// .query_srq = virtio_rdma_query_srq,
	// .destroy_srq = virtio_rdma_destroy_srq,
	// .post_srq_recv = virtio_rdma_post_srq_recv,

	.create_qp = virtio_rdma_create_qp,
	.query_qp = virtio_rdma_query_qp,
	.modify_qp = virtio_rdma_modify_qp,
	.destroy_qp = virtio_rdma_destroy_qp,

	.post_send = virtio_rdma_post_send,
	.post_recv = virtio_rdma_post_recv,
	.create_ah = virtio_rdma_create_ah,
	.destroy_ah = virtio_rdma_destroy_ah,
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
