/*
 * NVMe over Fabrics TCP target.
 * Copyright (c) 2016-2017, Rip Sohan <rip.sohan@verrko.com>
 * Copyright (c) 2016-2017, Solarflare Communications Inc.
 *      <linux-net-drivers@solarflare.com>
 * Copyright (c) 2016-2017, Lucian Carata <lucian.carata@cl.cam.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/nsproxy.h>
#include <linux/nvme.h>
#include <linux/socket.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/linux/tcp.h>
#include "nvmet.h"

#define NVMET_TCP_MAX_REQ_DATA_SIZE 131072

#define NVMET_SOCK_CONNECTED  BIT(0)
#define NVMET_CTRL_CONNECTED  BIT(1)
#define NVMET_ACCEPT_REQUESTS BIT(2)

/**
 * struct nvmet_tcp_listener - state related to a listening nvmet port
 * @rwork:         work item for receive
 * @relwork:       work item for closing the listener, run on general queue
 * @workqueue:     workqueue for listener-specific work
 * @kref:          reference count; a reference is taken per connection
 * @sock:          listening socket
 * @nvmet_port:    the associated NVMe port
 * @list:          list entry, inserted in #nvmet_tcp_listener_list
 * @wq_index:      index for workqueue name for #workqueue and connection wqs
 * @conn_wq_index: index for naming connection specific workqueues
 */
struct nvmet_tcp_listener {
	struct work_struct         rwork;
	struct work_struct         relwork;
	struct workqueue_struct   *workqueue;
	struct kref                kref;
	struct socket             *sock;
	struct nvmet_port         *nvmet_port;
	struct list_head           list;
	u16                        wq_index;
	u16                        conn_wq_index;
};

/**
 * struct nvmet_tcp_connection - state related to an active connection
 * @rwork:         work item for receive
 * @swork:         work item for send
 * @delwork:       work item for ctrl deletion
 * @relwork:       work item for closing the connection, run on listener queue
 * @workqueue:     workqueue for connection-specific work
 * @kref:          reference count; a reference is taken per pending request
 * @flags:         flags bitmap
 * @sock:          connected socket
 * @listener:      the associated listener
 * @nvme_sq:       submission queue
 * @nvme_cq:       completion queue
 * @requests:      list of requests awaiting response from the core
 * @responses:     list of requests with a response, queued for sending
 * @request_lock:  lock for protecting #requests and #responses lists
 * @rx_request:    the current request being received
 * @tx_request:    the current request response being sent
 * @list:          list entry, inserted in #nvmet_tcp_connection_list
 */
struct nvmet_tcp_connection {
	struct work_struct         rwork;
	struct work_struct         swork;
	struct work_struct         delwork;
	struct work_struct         relwork;
	struct workqueue_struct   *workqueue;
	struct kref                kref;
	unsigned long              flags;
	struct socket             *sock;
	struct nvmet_tcp_listener *listener;
	struct nvmet_sq            nvme_sq;
	struct nvmet_cq            nvme_cq;
	struct list_head           requests;
	struct list_head           responses;
	spinlock_t                 request_lock;
	struct nvmet_tcp_request  *rx_request;
	struct nvmet_tcp_request  *tx_request;
	struct list_head           list;
};

/**
 * enum nvmet_tcp_request_state - possible request states
 * @NVMET_TCP_REQ_AWAITING_CMD      : awaiting reception of complete command
 * @NVMET_TCP_REQ_AWAITING_DATA     : awaiting reception of complete payload
 * @NVMET_TCP_REQ_AWAITING_RESPONSE : request with nvmet core
 * @NVMET_TCP_REQ_SENDING_RESPONSE  : sending completion header
 * @NVMET_TCP_REQ_SENDING_DATA      : sending response payload
 * @NVMET_TCP_REQ_RESPONDED         : all data sent
 */
enum nvmet_tcp_request_state {
	NVMET_TCP_REQ_AWAITING_CMD,
	NVMET_TCP_REQ_AWAITING_DATA,
	NVMET_TCP_REQ_AWAITING_RESPONSE,
	NVMET_TCP_REQ_SENDING_RESPONSE,
	NVMET_TCP_REQ_SENDING_DATA,
	NVMET_TCP_REQ_RESPONDED,
};

/**
 * struct nvmet_tcp_request - state related to an active request
 * @connection       : the associated connection
 * @list             : list entry, inserted in connection.requests or responses
 * @req              : NVMe-oF request structure
 * @cmd              : NVMe-oF command
 * @rsp              : completion structure
 * @scatterlist      : pointer to SG list, NULL if no associated payload
 * @current_buf      : pointer to current buffer for rx or tx
 * @current_page     : pointer to current page for tx
 * @current_offset   : offset in #current_page
 * @current_expected : amount of data remaining for rx/tx
 * @current_sg       : the current SG list entry
 * @state            : request state
 * @sflags           : NVMe-oF status flags
 */
struct nvmet_tcp_request {
	struct nvmet_tcp_connection *connection;
	struct list_head             list;
	struct nvmet_req             req;
	struct nvme_command          cmd;
	struct nvme_completion       rsp;
	struct sg_table              sg_table;
	void                        *current_buf;
	struct page                 *current_page;
	size_t                       current_offset;
	int                          current_expected;
	struct scatterlist          *current_sg;
	enum nvmet_tcp_request_state state;
	u16                          sflags;
};

static int nvmet_tcp_add_port(struct nvmet_port *nvmet_port);
static void nvmet_tcp_remove_port(struct nvmet_port *nvmet_port);
static void nvmet_tcp_queue_response(struct nvmet_req *req);
static void nvmet_tcp_delete_ctrl(struct nvmet_ctrl *ctrl);

static struct nvmet_fabrics_ops nvmet_tcp_ops = {
	.owner            = THIS_MODULE,
	.type             = NVMF_TRTYPE_TCP,
	.sqe_inline_size  = NVMET_TCP_MAX_REQ_DATA_SIZE,
	.msdbd            = 1,
	.has_keyed_sgls   = 0,
	.add_port         = nvmet_tcp_add_port,
	.remove_port      = nvmet_tcp_remove_port,
	.queue_response   = nvmet_tcp_queue_response,
	.delete_ctrl      = nvmet_tcp_delete_ctrl,
};

/* Reference count management. */
static void listener_get(struct nvmet_tcp_listener *listener);
static void listener_put(struct nvmet_tcp_listener *listener);
static void connection_get(struct nvmet_tcp_connection *connection);
static void connection_put(struct nvmet_tcp_connection *connection);

static void request_destroy(struct nvmet_tcp_request *request);

static LIST_HEAD(nvmet_tcp_listener_list);
static DEFINE_MUTEX(nvmet_tcp_listener_mutex);

static LIST_HEAD(nvmet_tcp_connection_list);
static DEFINE_MUTEX(nvmet_tcp_connection_mutex);

static struct kmem_cache *request_cache;

/*
 * Connection handling.
 */
static void connection_kref_release(struct kref *kref)
{
	struct nvmet_tcp_connection *connection;

	/* Schedule the rest of the work in the per-listener workqueue. */
	connection = container_of(kref, struct nvmet_tcp_connection, kref);
	queue_work(connection->listener->workqueue, &connection->relwork);
}

static void connection_release_work(struct work_struct *work)
{
	struct nvmet_tcp_connection *connection;
	struct nvmet_tcp_request *request, *n;
	struct nvmet_tcp_listener *listener;
	struct sock *sk;

	connection = container_of(work, struct nvmet_tcp_connection, relwork);
	listener = connection->listener;

	pr_debug("Closing connection %p\n", connection);

	clear_bit(NVMET_ACCEPT_REQUESTS, &connection->flags);

	/* Destroy (and implicitly drain) the connection workqueue. */
	destroy_workqueue(connection->workqueue);
	connection->workqueue = NULL;

	mutex_lock(&nvmet_tcp_connection_mutex);
	list_del_init(&connection->list);
	mutex_unlock(&nvmet_tcp_connection_mutex);

	/* Requests that are with the NVME core will hold a reference to the
	 * connection, so will have completed before we get here. Thus they
	 * are ours to destroy - we grab the spin lock out of politeness.
	 */
	spin_lock(&connection->request_lock);
	connection->rx_request = NULL;
	list_for_each_entry_safe(request, n, &connection->requests, list) {
		list_del_init(&request->list);
		request_destroy(request);
	}
	list_for_each_entry_safe(request, n, &connection->responses, list) {
		list_del_init(&request->list);
		request_destroy(request);
	}
	spin_unlock(&connection->request_lock);

	if (test_and_clear_bit(NVMET_SOCK_CONNECTED, &connection->flags)) {
		sk = connection->sock->sk;

		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		write_unlock_bh(&sk->sk_callback_lock);

		kernel_sock_shutdown(connection->sock, SHUT_RDWR);
		sock_release(connection->sock);
		connection->sock = NULL;
	}

	kfree(connection);

	listener_put(listener);
}

static void connection_get(struct nvmet_tcp_connection *connection)
{
	kref_get(&connection->kref);
}

static void connection_put(struct nvmet_tcp_connection *connection)
{
	kref_put(&connection->kref, connection_kref_release);
}

static void connection_close(struct nvmet_tcp_connection *connection)
{
	if (test_and_clear_bit(NVMET_ACCEPT_REQUESTS, &connection->flags))
		connection_put(connection);
}

static void connection_delete_work(struct work_struct *work)
{
	struct nvmet_tcp_connection *connection;

	connection = container_of(work, struct nvmet_tcp_connection, delwork);

	/* This blocks until asynchronous events have been completed. */
	nvmet_sq_destroy(&connection->nvme_sq);
	connection_close(connection);
}

static void connection_delete_ctrl(struct nvmet_tcp_connection *connection)
{
	if (!test_and_clear_bit(NVMET_CTRL_CONNECTED, &connection->flags))
		return;

	/* We use the per-listener workqueue here, rather than the connection
	 * specific one. We'll want the connection specific one for sending
	 * responses via nvmet_sq_destroy.
	 */
	queue_work(connection->listener->workqueue, &connection->delwork);
}

static void request_destroy_sgl(struct nvmet_tcp_request *request)
{
	struct scatterlist *sg = request->sg_table.sgl;
	struct page *page;

	while (sg) {
		page = sg_page(sg);
		if (page)
			__free_pages(page, 0);
		sg = sg_next(sg);
	}

	sg_free_table_chained(&request->sg_table, false);
}

static int request_create_sgl(struct nvmet_tcp_request *request, u32 len)
{
	struct scatterlist *sg;
	struct page *page;
	int page_count;
	int rc;
	int i;

	page_count = DIV_ROUND_UP(len, PAGE_SIZE);

	if (!page_count) {
		request->sg_table.sgl = NULL;
		request->req.sg = NULL;
		return 0;
	}

	rc = sg_alloc_table_chained(&request->sg_table, page_count, NULL);
	if (rc)
		return rc;

	sg = request->sg_table.sgl;

	for (i = 0; i < page_count; i++) {
		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto err;
		sg_set_page(sg, page, len > PAGE_SIZE ? PAGE_SIZE : len, 0);
		len -= PAGE_SIZE;
		sg = sg_next(sg);
	}

	request->req.sg = request->sg_table.sgl;
	request->req.sg_cnt = request->sg_table.nents;

	return 0;

err:
	request_destroy_sgl(request);

	return -ENOMEM;
}

static void request_destroy(struct nvmet_tcp_request *request)
{
	request_destroy_sgl(request);
	kmem_cache_free(request_cache, request);
}

static struct nvmet_tcp_request *request_create(
		struct nvmet_tcp_connection *connection)
{
	struct nvmet_tcp_request *request;
	unsigned long flags;

	request = kmem_cache_alloc(request_cache, GFP_KERNEL);
	if (!request)
		return ERR_PTR(-ENOMEM);

	request->req.cmd = &request->cmd;
	request->req.rsp = &request->rsp;
	request->req.port = connection->listener->nvmet_port;
	INIT_LIST_HEAD(&request->list);
	request->connection = connection;
	request->state = NVMET_TCP_REQ_AWAITING_CMD;

	request->current_buf = &request->cmd;
	request->current_expected = sizeof(request->cmd);
	request->current_page = NULL;
	request->current_offset = 0;
	request->current_sg = NULL;
	request->sg_table.sgl = NULL;

	spin_lock_irqsave(&connection->request_lock, flags);
	connection->rx_request = request;
	list_add_tail(&request->list, &connection->requests);
	spin_unlock_irqrestore(&connection->request_lock, flags);

	return request;
}

static int request_get_sg_list(struct nvmet_tcp_request *request)
{
	struct nvme_sgl_desc *sgl = &request->cmd.common.dptr.sgl;
	int sgl_desc_subtype = sgl->type & 0x0f;
	int sgl_desc_type = sgl->type >> 4;
	u32 len;
	int rc;

	len = le32_to_cpu(sgl->length);
	if (len == 0)
		/* No data needed. */
		return 0;

	if (sgl_desc_type != NVME_SGL_FMT_DATA_DESC ||
	    sgl_desc_subtype != NVME_SGL_FMT_OFFSET) {
		request->sflags = NVME_SC_SGL_INVALID_TYPE | NVME_SC_DNR;
		return -EBADMSG;
	}

	if (le64_to_cpu(sgl->addr)) {
		request->sflags = NVME_SC_SGL_INVALID_OFFSET | NVME_SC_DNR;
		return -EBADMSG;
	}

	if (len > NVMET_TCP_MAX_REQ_DATA_SIZE) {
		request->sflags = NVME_SC_SGL_INVALID_DATA | NVME_SC_DNR;
		return -EBADMSG;
	}

	rc = request_create_sgl(request, len);
	if (rc) {
		request->sflags = NVME_SC_INTERNAL | NVME_SC_DNR;
		return rc;
	}

	/* Return amount of data we expect to receive with the request. */
	if (!nvme_is_write(&request->cmd))
		return 0;

	return len;
}

static void request_received(struct nvmet_tcp_connection *connection,
		struct nvmet_tcp_request *request, int status)
{
	/* Get a reference to this connection, held until the request
	 * is completed. We do this regardless of the error state. This
	 * reference is dropped at NVMET_TCP_REQ_RESPONDED.
	 */
	connection_get(connection);

	/* Prepare to receive the next request. */
	connection->rx_request = NULL;

	request->current_buf = NULL;
	request->current_expected = 0;
	request->current_sg = NULL;
	request->state = NVMET_TCP_REQ_AWAITING_RESPONSE;

	if (request->cmd.common.opcode == nvme_fabrics_command)
		pr_debug("fabrics command %#x received%s\n",
				request->cmd.fabrics.fctype,
				status ? " - internal failure" : "");
	else
		pr_debug("command %#x received %s\n",
				request->cmd.common.opcode,
				status ? " - internal failure" : "");

	if (!status)
		request->req.execute(&request->req);
	else
		nvmet_req_complete(&request->req, request->sflags);
}

static void request_received_bad(struct nvmet_tcp_connection *connection,
		struct nvmet_tcp_request *request)
{
	/* Get a reference to this connection, held until the request
	 * is completed. We do this regardless of the error state. This
	 * reference is dropped at NVMET_TCP_REQ_RESPONDED.
	 */
	connection_get(connection);

	/* Prepare to receive the next request. */
	connection->rx_request = NULL;

	request->current_buf = NULL;
	request->current_expected = 0;
	request->current_sg = NULL;

	/* We don't modify request->state in here, because queue_response will
	 * have already been called, by __nvmet_req_complete in nvmet_req_init
	 */

	if (request->cmd.common.opcode == nvme_fabrics_command)
		pr_err("fabrics command %#x received but req_init_failed\n",
				request->cmd.fabrics.fctype);
	else
		pr_err("command %#x received but req_init_failed\n",
				request->cmd.common.opcode);
}

static int connection_recv_from_sock(struct nvmet_tcp_connection *connection,
		void *buf, size_t buf_len)
{
	struct msghdr msg = {};
	struct kvec iov;
	int rc;

	iov.iov_base = buf;
	iov.iov_len = buf_len;

	rc = kernel_recvmsg(connection->sock, &msg, &iov, 1, iov.iov_len,
			MSG_DONTWAIT);

	if (rc == 0 || rc == -EAGAIN) {
		rc = -EAGAIN;
	} else if (rc < 0) {
		pr_err("recv failed with %d, closing\n", rc);
		connection_close(connection);
	}

	return rc;
}

static int connection_recv(struct nvmet_tcp_connection *connection)
{
	struct nvmet_tcp_request *request;
	int buf_len;
	void *buf;
	int rc;

	if (connection->rx_request)
		request = connection->rx_request;
	else
		request = request_create(connection);

	if (IS_ERR(request))
		return PTR_ERR(request);

	buf = request->current_buf;
	buf_len = request->current_expected;

	if (!buf) {
		/* This shouldn't happen - we're not expecting data. */
		pr_err("%s not expecting data\n", __func__);
		connection_close(connection);
		return -EINVAL;
	}

	rc = connection_recv_from_sock(connection, buf, buf_len);
	if (rc <= 0)
		return rc;

	request->current_buf += rc;
	request->current_expected -= rc;

	if (request->current_expected > 0)
		return -EAGAIN;

	rc = 0;

	switch (request->state) {
	case NVMET_TCP_REQ_AWAITING_CMD:
		/* We should now have a complete command header. */
		rc = nvmet_req_init(&request->req,
				&connection->nvme_cq, &connection->nvme_sq,
				&nvmet_tcp_ops);
		if (!rc) {
			/* If nvmet_req_init failed it will have called
			 * nvmet_req_complete for us, which will call
			 * queue_response.
			 */
			request_received_bad(connection, request);
			return -EBADMSG;
		}

		rc = request_get_sg_list(request);

		if (rc > 0) {
			request->current_sg = request->req.sg;
			request->current_buf = sg_virt(request->current_sg);
			request->current_expected = request->current_sg->length;
			request->state = NVMET_TCP_REQ_AWAITING_DATA;
		} else {
			request_received(connection, request, rc);
		}
		break;

	case NVMET_TCP_REQ_AWAITING_DATA:
		request->current_sg = sg_next(request->current_sg);
		if (!request->current_sg) {
			request_received(connection, request, rc);
		} else {
			request->current_buf = sg_virt(request->current_sg);
			request->current_expected = request->current_sg->length;
		}
		break;

	default:
		break;
	}

	return 0;
}

static void connection_rwork(struct work_struct *work)
{
	struct nvmet_tcp_connection *connection;
	int count = 0;
	int rc;

	connection = container_of(work, struct nvmet_tcp_connection, rwork);

	while (test_bit(NVMET_ACCEPT_REQUESTS, &connection->flags)) {
		rc = connection_recv(connection);

		if (rc < 0)
			break;

		if (count++ > 10) {
			cond_resched();
			count = 0;
		}
	}

	connection_put(connection);
}

static void connection_data_ready(struct sock *sk)
{
	struct nvmet_tcp_connection *connection;

	read_lock_bh(&sk->sk_callback_lock);
	connection = sk->sk_user_data;
	if (!connection)
		goto out;
	connection_get(connection);
	if (!queue_work(connection->workqueue, &connection->rwork))
		connection_put(connection);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static int connection_send_to_sock(struct nvmet_tcp_connection *connection,
				   struct nvmet_tcp_request *request,
				   int flags)
{
	int rc;

	if (request->current_page) {
		rc = kernel_sendpage(connection->sock, request->current_page,
				request->current_offset,
				request->current_expected, flags);

		if (rc > 0) {
			request->current_offset += rc;
			request->current_expected -= rc;
		}
	} else {
		struct msghdr msg = {};
		struct kvec iov;

		msg.msg_flags = flags;
		iov.iov_base = request->current_buf;
		iov.iov_len = request->current_expected;

		rc = kernel_sendmsg(connection->sock, &msg, &iov, 1,
				iov.iov_len);

		if (rc > 0) {
			request->current_buf += rc;
			request->current_expected -= rc;
		}
	}

	if (request->current_expected == 0)
		rc = 0;
	else if (rc >= 0 || rc == -EAGAIN)
		rc = -EAGAIN;
	else if (rc < 0)
		connection_close(connection);

	return rc;
}

static void connection_swork(struct work_struct *work)
{
	struct nvmet_tcp_connection *connection;
	struct nvmet_tcp_request *request = NULL;
	struct scatterlist *sg;
	struct nvmet_req *req;
	int msg_flags = 0;
	int count = 0;
	int rc;

	connection = container_of(work, struct nvmet_tcp_connection, swork);

	while (test_bit(NVMET_SOCK_CONNECTED, &connection->flags)) {
		if (!request)
			request = connection->tx_request;

		if (!request) {
			spinlock_t *lock = &connection->request_lock;
			unsigned long flags;

			/* Get the next response from the queue. */
			spin_lock_irqsave(lock, flags);
			if (list_empty(&connection->responses)) {
				/* No responses queued. */
				spin_unlock_irqrestore(lock, flags);
				break;
			}
			request = list_first_entry(&connection->responses,
					struct nvmet_tcp_request, list);
			list_del(&request->list);
			spin_unlock_irqrestore(lock, flags);

			connection->tx_request = request;
			req = &request->req;

			if (nvme_is_write(req->cmd)) {
				pr_debug("Sending response to write with status %#x\n",
						req->rsp->status);
			} else {
				pr_debug("Sending response to read with status %#x, length %zu\n",
						req->rsp->status,
						req->data_len);
				if ((req->rsp->status == 0) && req->data_len)
					msg_flags |= MSG_MORE;
			}
		}

		rc = connection_send_to_sock(connection, request, msg_flags);
		msg_flags &= ~MSG_MORE;
		if (rc == -EAGAIN)
			break;

		if (rc < 0) {
			pr_err("Bad error %d when sending in state %d\n", rc,
					request->state);
			break;
		}

		switch (request->state) {
		case NVMET_TCP_REQ_SENDING_RESPONSE:
			/* Finished sending response header. Move on to data
			 * if needed.
			 */
			req = &request->req;

			if (!nvme_is_write(req->cmd) && req->data_len &&
			    req->rsp->status == 0) {
				sg = request->req.sg;

				request->current_sg = sg;
				request->current_page = sg_page(sg);
				request->current_offset = 0;
				request->current_expected = sg->length;
				request->state = NVMET_TCP_REQ_SENDING_DATA;
			} else {
				request->state = NVMET_TCP_REQ_RESPONDED;
			}
			break;

		case NVMET_TCP_REQ_SENDING_DATA:
			sg = sg_next(request->current_sg);
			if (sg) {
				request->current_sg = sg;
				request->current_page = sg_page(sg);
				request->current_offset = 0;
				request->current_expected = sg->length;
			} else {
				request->state = NVMET_TCP_REQ_RESPONDED;
			}
			break;

		default:
			pr_err("Unexpected state %d during response\n",
				request->state);
			/* Drop through. */
		}

		if (request->state == NVMET_TCP_REQ_RESPONDED) {
			request_destroy(request);
			request = NULL;
			connection->tx_request = NULL;
			connection_put(connection);
		}

		if (count++ > 10) {
			cond_resched();
			count = 0;
		}
	}

	connection_put(connection);
}

static void connection_write_space(struct sock *sk)
{
	struct nvmet_tcp_connection *connection;

	read_lock_bh(&sk->sk_callback_lock);
	connection = sk->sk_user_data;
	if (!connection)
		goto out;
	connection_get(connection);
	if (!queue_work(connection->workqueue, &connection->swork))
		connection_put(connection);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static struct nvmet_tcp_connection *connection_create(
		struct nvmet_tcp_listener *listener,
		struct socket *socket)
{
	struct nvmet_tcp_connection *connection = NULL;
	u16 wq_index;
	int optval;
	int rc = 0;

	connection = kzalloc(sizeof(*connection), GFP_KERNEL);
	if (!connection)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&nvmet_tcp_connection_mutex);
	wq_index = listener->conn_wq_index++;
	mutex_unlock(&nvmet_tcp_connection_mutex);

	connection->workqueue = alloc_ordered_workqueue("nvmet-tcp-l%04x-c%04x",
			0, listener->wq_index, wq_index);
	if (!connection->workqueue) {
		kfree(connection);
		return ERR_PTR(-ENOMEM);
	}

	listener_get(listener);

	rc = nvmet_sq_init(&connection->nvme_sq);
	if (rc)
		goto err;

	connection->listener = listener;
	connection->sock = socket;
	INIT_LIST_HEAD(&connection->list);
	INIT_LIST_HEAD(&connection->requests);
	INIT_LIST_HEAD(&connection->responses);
	spin_lock_init(&connection->request_lock);
	INIT_WORK(&connection->rwork, connection_rwork);
	INIT_WORK(&connection->swork, connection_swork);
	INIT_WORK(&connection->delwork, connection_delete_work);
	INIT_WORK(&connection->relwork, connection_release_work);
	kref_init(&connection->kref);
	set_bit(NVMET_SOCK_CONNECTED, &connection->flags);
	set_bit(NVMET_CTRL_CONNECTED, &connection->flags);
	set_bit(NVMET_ACCEPT_REQUESTS, &connection->flags);

	write_lock_bh(&socket->sk->sk_callback_lock);
	socket->sk->sk_data_ready = connection_data_ready;
	socket->sk->sk_write_space = connection_write_space;
	socket->sk->sk_user_data = connection;
	write_unlock_bh(&socket->sk->sk_callback_lock);

	optval = 1;
	kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY,
			(char*)&optval, sizeof(optval));

	mutex_lock(&nvmet_tcp_connection_mutex);
	list_add(&connection->list, &nvmet_tcp_connection_list);
	mutex_unlock(&nvmet_tcp_connection_mutex);

	return connection;

err:
	destroy_workqueue(connection->workqueue);
	kfree(connection);
	listener_put(listener);

	return ERR_PTR(rc);
}


/*
 * Listener handling.
 */
static int listener_accept(struct nvmet_tcp_listener *listener)
{
	struct nvmet_tcp_connection *connection = NULL;
	struct socket *newsock = NULL;
	int rc;

	rc = kernel_accept(listener->sock, &newsock, O_NONBLOCK);
	if (rc < 0)
		goto err;

	newsock->sk->sk_sndtimeo = 1;

	connection = connection_create(listener, newsock);
	if (IS_ERR(connection)) {
		rc = PTR_ERR(connection);
		goto err;
	}

	pr_debug("accepted connection %p\n", connection);

	/* Wake up receiving socket. */
	newsock->sk->sk_data_ready(newsock->sk);

	return 0;

err:
	return rc;
}

static void listener_rwork(struct work_struct *work)
{
	struct nvmet_tcp_listener *listener;
	int count = 0;
	int rc;

	listener = container_of(work, struct nvmet_tcp_listener, rwork);

	while (1) {
		rc = listener_accept(listener);
		if (rc)
			break;

		if (count++ > 10) {
			cond_resched();
			count = 0;
		}
	}
}

static void listener_data_ready(struct sock *sk)
{
	struct nvmet_tcp_listener *listener;

	read_lock_bh(&sk->sk_callback_lock);
	listener = sk->sk_user_data;
	queue_work(listener->workqueue, &listener->rwork);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void listener_sock_destroy(struct nvmet_tcp_listener *listener)
{
	if (!listener->sock)
		return;

	kernel_sock_shutdown(listener->sock, SHUT_RDWR);
	sock_release(listener->sock);

	listener->sock = NULL;
}

static int listener_sock_create(struct nvmet_tcp_listener *listener)
{
	struct nvmf_disc_rsp_page_entry *disc_addr;
	struct socket *sock = NULL;
	struct sockaddr_in sa;
	u16 port_in;
	int rc;

	disc_addr = &listener->nvmet_port->disc_addr;

	switch (disc_addr->adrfam) {
	case NVMF_ADDR_FAMILY_IP4:
		break;
	case NVMF_ADDR_FAMILY_IP6:
		/* TODO: add IPv6 support. */
	default:
		pr_err("address family %d not supported\n", disc_addr->adrfam);
		return -EINVAL;
	}

	rc = kstrtou16(disc_addr->trsvcid, 0, &port_in);
	if (rc)
		return rc;

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = in_aton(disc_addr->traddr);
	sa.sin_port = htons(port_in);

	rc = sock_create_kern(current->nsproxy->net_ns,
			      PF_INET, SOCK_STREAM, 0, &sock);
	if (rc < 0)
		goto err;
	listener->sock = sock;

	rc = kernel_bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready = listener_data_ready;
	sock->sk->sk_user_data = listener;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	rc = kernel_listen(sock, 0);
	if (rc < 0)
		goto err;

	/* Check for connections immediately. */
	listener_data_ready(sock->sk);

	return rc;

err:
	listener_sock_destroy(listener);
	return rc;
}

static void listener_kref_release(struct kref *kref)
{
	struct nvmet_tcp_listener *listener;

	listener = container_of(kref, struct nvmet_tcp_listener, kref);

	/* Schedule the rest of the work in the shared system workqueue -
	 * we may be on the listener workqueue, and we're about to drain it.
	 */
	schedule_work(&listener->relwork);
}

static void listener_release_work(struct work_struct *work)
{
	struct nvmet_tcp_listener *listener;

	listener = container_of(work, struct nvmet_tcp_listener, relwork);
	destroy_workqueue(listener->workqueue);

	mutex_lock(&nvmet_tcp_listener_mutex);
	list_del_init(&listener->list);
	mutex_unlock(&nvmet_tcp_listener_mutex);

	listener_sock_destroy(listener);
	kfree(listener);
	module_put(THIS_MODULE);
}

static void listener_get(struct nvmet_tcp_listener *listener)
{
	kref_get(&listener->kref);
}

static void listener_put(struct nvmet_tcp_listener *listener)
{
	kref_put(&listener->kref, listener_kref_release);
}

/*
 * NVMET ops
 */
static int nvmet_tcp_add_port(struct nvmet_port *nvmet_port)
{
	struct nvmet_tcp_listener *listener;
	static u16 wq_index;
	int rc;

	if (!try_module_get(THIS_MODULE))
		return -EINVAL;

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener) {
		module_put(THIS_MODULE);
		return -ENOMEM;
	}

	listener->wq_index = wq_index++;
	listener->workqueue = alloc_ordered_workqueue("nvmet-tcp-l%04x", 0,
			listener->wq_index);
	if (!listener->workqueue) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_WORK(&listener->rwork, listener_rwork);
	INIT_WORK(&listener->relwork, listener_release_work);
	kref_init(&listener->kref);
	listener->nvmet_port = nvmet_port;
	nvmet_port->priv = listener;

	rc = listener_sock_create(listener);
	if (rc < 0)
		goto err;

	mutex_lock(&nvmet_tcp_listener_mutex);
	list_add_tail(&listener->list, &nvmet_tcp_listener_list);
	mutex_unlock(&nvmet_tcp_listener_mutex);

	return 0;

err:
	listener_sock_destroy(listener);
	kfree(listener);
	module_put(THIS_MODULE);

	return rc;
}

static void nvmet_tcp_remove_port(struct nvmet_port *nvmet_port)
{
	struct nvmet_tcp_connection *connection;
	struct nvmet_tcp_listener *listener;

	listener = nvmet_port->priv;

	/* Finish up any existing connections. */
restart:
	mutex_lock(&nvmet_tcp_connection_mutex);
	list_for_each_entry(connection, &nvmet_tcp_connection_list, list) {
		if (connection->listener == listener) {
			list_del_init(&connection->list);
			mutex_unlock(&nvmet_tcp_connection_mutex);
			connection_delete_ctrl(connection);
			goto restart;
		}
	}

	mutex_unlock(&nvmet_tcp_connection_mutex);

	listener_put(listener);
}

static void nvmet_tcp_queue_response(struct nvmet_req *req)
{
	struct nvmet_tcp_connection *connection;
	struct nvmet_tcp_request *request;
	unsigned long flags;

	request = container_of(req, struct nvmet_tcp_request, req);

	/* There are two possible ways for us to get here:
	 *  - a request has been completed, either in failure or success. In
	 *    this case the request will be in NVMET_TCP_REQ_AWAITING_RESPONSE.
	 *  - if nvmet_req_init fails we will be called immediately, while
	 *    still in NVMET_TCP_REQ_AWAITING_CMD.
	 */
	if (cmpxchg(&request->state, NVMET_TCP_REQ_AWAITING_RESPONSE,
		    NVMET_TCP_REQ_SENDING_RESPONSE) ==
	    NVMET_TCP_REQ_AWAITING_RESPONSE)
		goto valid;

	if (cmpxchg(&request->state, NVMET_TCP_REQ_AWAITING_CMD,
		    NVMET_TCP_REQ_SENDING_RESPONSE) ==
	    NVMET_TCP_REQ_AWAITING_CMD)
		goto valid;

	pr_err("Unexpected request state %d\n", request->state);
	return;

valid:
	request->current_buf = req->rsp;
	request->current_expected = sizeof(*req->rsp);
	connection = request->connection;

	if (req->rsp->status) {
		if (req->cmd->common.opcode == nvme_fabrics_command)
			pr_err("fabrics command %#x failed with status %#x (exec function %pf)\n",
					req->cmd->fabrics.fctype,
					req->rsp->status, req->execute);
		else
			pr_err("command %#x failed with status %#x (exec function %pf)\n",
					req->cmd->common.opcode,
					req->rsp->status, req->execute);
	}

	/* Queue response for sending. Can be in IRQ context, but not always. */
	spin_lock_irqsave(&connection->request_lock, flags);
	list_move_tail(&request->list, &connection->responses);
	spin_unlock_irqrestore(&connection->request_lock, flags);

	/* Activate sender in case we have space in the socket. */
	connection_get(connection);
	if (!queue_work(connection->workqueue, &connection->swork))
		connection_put(connection);
}

static void nvmet_tcp_delete_ctrl(struct nvmet_ctrl *ctrl)
{
	struct nvmet_tcp_connection *connection;

restart:
	mutex_lock(&nvmet_tcp_connection_mutex);
	list_for_each_entry(connection, &nvmet_tcp_connection_list, list) {
		if (connection->nvme_sq.ctrl == ctrl) {
			list_del_init(&connection->list);
			mutex_unlock(&nvmet_tcp_connection_mutex);
			connection_delete_ctrl(connection);
			goto restart;
		}
	}

	mutex_unlock(&nvmet_tcp_connection_mutex);
}

static int __init nvmet_tcp_init(void)
{
	request_cache = kmem_cache_create("nvmet_tcp_request",
			sizeof(struct nvmet_tcp_request), 0, 0, NULL);
	return nvmet_register_transport(&nvmet_tcp_ops);
}


static void __exit nvmet_tcp_exit(void)
{
	struct nvmet_tcp_listener *listener, *n;

	nvmet_unregister_transport(&nvmet_tcp_ops);

	mutex_lock(&nvmet_tcp_listener_mutex);
	list_for_each_entry_safe(listener, n, &nvmet_tcp_listener_list, list) {
		mutex_unlock(&nvmet_tcp_listener_mutex);
		nvmet_tcp_remove_port(listener->nvmet_port);
		mutex_lock(&nvmet_tcp_listener_mutex);
	}
	mutex_unlock(&nvmet_tcp_listener_mutex);

	kmem_cache_destroy(request_cache);
}

module_init(nvmet_tcp_init);
module_exit(nvmet_tcp_exit);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("nvmet-transport-3");  /* 3 == NVMF_TRTYPE_TCP */
