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

#ifndef __VIRTIO_RDMA_H__
#define __VIRTIO_RDMA_H__

#include <infiniband/driver.h>
#include <infiniband/kern-abi.h>

struct virtio_rdma_device {
	struct verbs_device	ibv_dev;
};

struct virtio_rdma_context {
	struct verbs_context	ibv_ctx;
};

inline struct virtio_rdma_device* to_vdev(struct ibv_device* ibv_dev) {
    return container_of(ibv_dev, struct virtio_rdma_device, ibv_dev.device);
}

inline struct virtio_rdma_context* to_vctx(struct ibv_context* ibv_ctx) {
    return container_of(ibv_ctx, struct virtio_rdma_context, ibv_ctx.context);
}

#endif
