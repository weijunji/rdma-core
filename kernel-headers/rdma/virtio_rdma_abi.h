/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
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

#ifndef __VIRTIO_RDMA_ABI_H__
#define __VIRTIO_RDMA_ABI_H__

#include <linux/types.h>

#define VIRTIO_RDMA_ABI_VERSION 1

struct virtio_rdma_create_qp_uresp {
    __u64 sq_offset;
    __u64 sq_size;
    __u64 sq_phys_addr;
    __u32 svq_size;
    int num_sqe;
    int num_svqe;
    int sq_idx;

    __u64 rq_offset;
    __u64 rq_size;
    __u64 rq_phys_addr;
    __u32 rvq_size;
    int num_rqe;
    int num_rvqe;
    int rq_idx;

    __u32 vq_align;
    __u32 page_size;

    __u32 qpn;
};

struct virtio_rdma_create_cq_uresp {
    __u64 offset;
    __u64 cq_size;
    __u64 cq_phys_addr;
    __u32 vq_align;
    __u32 vq_size;
    int num_cqe;
    int num_cvqe;
};

struct virtio_rdma_cqe {
	__u64		wr_id;
	__u32 status;
	__u32 opcode;
	__u32 vendor_err;
	__u32 byte_len;
	__u32 imm_data;
	__u32 qp_num;
	__u32 src_qp;
	int	 wc_flags;
	__u16 pkey_index;
	__u16 slid;
	__u8 sl;
	__u8 dlid_path_bits;
};

enum {
	VIRTIO_RDMA_NOTIFY_NOT = (0),
	VIRTIO_RDMA_NOTIFY_SOLICITED = (1 << 0),
	VIRTIO_RDMA_NOTIFY_NEXT_COMPLETION = (1 << 1)
};

struct virtio_rdma_sge {
    __u64 addr;
    __u32 length;
    __u32 lkey;
};

struct virtio_rdma_cmd_post_send {
    __u32 qpn;
    __u32 is_kernel;
    __u32 num_sge;

    int send_flags;
    __u32 opcode;
    __u64 wr_id;

    union {
        __be32 imm_data;
        __u32 invalidate_rkey;
    } ex;
    
    union {
        struct {
            __u64 remote_addr;
            __u32 rkey;
        } rdma;
        struct {
            __u64 remote_addr;
            __u64 compare_add;
            __u64 swap;
            __u32 rkey;
        } atomic;
        struct {
            __u32 remote_qpn;
            __u32 remote_qkey;
            __u32 ahn;
        } ud;
        struct {
            __u32 mrn;
            __u32 key;
            int access;
        } reg;
    } wr;
};

struct virtio_rdma_cmd_post_recv {
	__u32 qpn;
	__u32 is_kernel;

	__u32 num_sge;
	__u64 wr_id;
};

#endif
