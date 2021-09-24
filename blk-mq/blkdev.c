#include "blkdev.h"
#include "ksocket.h"
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/llist.h>

#define BLKDEV_DEBUG	0

#define SUBMISSION_BATCH_SZ	1000

#define BLKDEV_ERRMSG printk(KERN_ERR "[%s %d] %s call %p \n", \
				__FILE__, __LINE__, __FUNCTION__, __builtin_return_address(0))

typedef struct {
	unsigned int op;
	loff_t offset;
	u64 size;
	u16 tag;
} packet_t;

typedef struct {
	struct llist_node node;
	struct request *rq;
} entry_t;

static int ncores;
static int *hctx_id;

static ksocket_t *sockets;
static struct llist_head *sqs;
static struct task_struct **sq_threads;
static struct task_struct **cq_threads;

/* Module parameters */
static struct sockaddr_in addr_srv;
static int addr_len;
static int blkdev_major = 0;
static block_dev_t *blkdev_dev = NULL;

ssize_t recv_packet(packet_t *packet, ksocket_t socket, char *buffer)
{
	int len;

	len = krecv(socket, packet, sizeof(packet_t), MSG_DONTWAIT);
	if (len == -EAGAIN) {
		return 0;
	} else if (len <= 0) {
		BLKDEV_ERRMSG;
		return len;
	}

#if BLKDEV_DEBUG
	printk("recv packet: op(%u) offset(%llu) size(%llu) tag(%u)\n",
			packet->op, packet->offset, packet->size, packet->tag);
#endif

	if (op_is_write(packet->op))
		return len;

	len = krecv(socket, buffer, packet->size, MSG_WAITALL);
	if (len <= 0)
		BLKDEV_ERRMSG;

	return len;
}

static void blkdev_completion(void *data)
{
	int id = (int)data;
	struct request *rq;

	packet_t packet;
	char *buffer;

	struct bio_vec bvec;
	struct req_iterator iter;
	loff_t pos = 0;

	buffer = kmalloc(2 * 1024 * 1024, GFP_KERNEL);
	if (!buffer) {
		BLKDEV_ERRMSG;
		return;
	}

	while (!kthread_should_stop()) {
		if (recv_packet(&packet, sockets[id], buffer) <= 0)
			continue;

		rq = blk_mq_tag_to_rq(blkdev_dev->tag_set.tags[0], packet.tag);
		if (!rq) {
			BLKDEV_ERRMSG;
			continue;
		}

		if (!op_is_write(packet.op)) {
			pos = 0;
			rq_for_each_segment(bvec, rq, iter) {
				unsigned long b_len = bvec.bv_len;
				void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

				memcpy(b_buf, buffer + pos, b_len);

				pos += b_len;
			}
		}

		blk_mq_complete_request(rq);
	}

	kfree(buffer);

	do_exit(0);
}

int send_packet(ksocket_t socket, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	packet_t packet;
	int len;

	packet.op = rq_data_dir(rq);
	packet.offset = blk_rq_pos(rq) << SECTOR_SHIFT;
	packet.size = blk_rq_bytes(rq);
	packet.tag = rq->tag;

#if BLKDEV_DEBUG
	printk("send packet: op(%u) offset(%llu) size(%llu) tag(%u)\n",
			packet.op, packet.offset, packet.size, packet.tag);
#endif

	len = ksend(socket, &packet, sizeof(packet_t), 0);
	if (len <= 0) {
		BLKDEV_ERRMSG;
		return len;
	}

	if (!op_is_write(packet.op))
		return 0;

	rq_for_each_segment(bvec, rq, iter) {
		unsigned long b_len = bvec.bv_len;
		void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

		len = ksend(socket, b_buf, b_len, 0);
		if (len <= 0) {
			BLKDEV_ERRMSG;
			return len;
		}
	}

	return len;
}

static void blkdev_submission(void *data)
{
	int id = (int)data;
	struct llist_node *node = NULL;
	entry_t *next;
	int batch = SUBMISSION_BATCH_SZ;

	while (!kthread_should_stop()) {
		while (!llist_empty(&sqs[id])) {
			node = llist_del_first(&sqs[id]);
			if (!node)
				break;

			next = llist_entry(node, entry_t, node);
			if (!next)
				break;

			send_packet(sockets[id], next->rq);

			kfree(next);

			if (!(--batch)) {
				batch = SUBMISSION_BATCH_SZ;
				break;
			}
		}
		io_schedule();
	}

	do_exit(0);
}

static entry_t *create_entry(struct request *rq)
{
	entry_t *entry;

	entry = kmalloc(sizeof(entry_t), GFP_KERNEL);
	if (!entry) {
		BLKDEV_ERRMSG;
		return NULL;
	}

	entry->rq = rq;

	return entry;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	entry_t *entry;
	struct request *rq = bd->rq;
	int id = hctx_id[smp_processor_id()];

	blk_mq_start_request(rq);

	entry = create_entry(rq);
	if (!entry)
		return BLK_STS_IOERR;

	llist_add(&entry->node, &sqs[id]);

	return BLK_STS_OK;
}

static void complete_rq(struct request *rq)
{
	blk_mq_end_request(rq, BLK_STS_OK);
}

static struct blk_mq_ops mq_ops = {
	.queue_rq = queue_rq,
	.complete = complete_rq
};

static int dev_open(struct block_device *bd, fmode_t mode)
{
	block_dev_t *dev = bd->bd_disk->private_data;
	if (dev == NULL) {
		BLKDEV_ERRMSG;
		return -ENXIO;
	}
	atomic_inc(&dev->open_counter);
	return 0;
}

static void dev_release(struct gendisk *gd, fmode_t mode)
{
	block_dev_t *dev = gd->private_data;
	if (dev == NULL)
		return;
	atomic_dec(&dev->open_counter);
}

static int dev_ioctl(struct block_device *bd, fmode_t mode, unsigned int cmd,
		unsigned long arg)
{
	return -ENOTTY;
}

static const struct block_device_operations blk_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_release,
	.ioctl = dev_ioctl,
};

static void clear_socket(ksocket_t socket)
{
	if (socket) {
		kshutdown(socket, SHUT_RDWR);
		kclose(socket);
	}
}

static void clear_sockets(void)
{
	int core;

	for (core=0; core<ncores; core++) {
		clear_socket(sockets[core]);
		sockets[core] = NULL;
	}

	kfree(sockets);
}

static int create_socket(ksocket_t *socket)
{
	*socket = ksocket(AF_INET, SOCK_STREAM, 0);
	if (*socket == NULL) {
		BLKDEV_ERRMSG;
		return -ENOMEM;
	}
	if (kconnect(*socket, (struct sockaddr*)&addr_srv, addr_len) < 0) {
		BLKDEV_ERRMSG;
		return -ENOTCONN;
	}
	return 0;
}

static int create_sockets(void)
{
	int ret;
	int core;

	sockets = kmalloc(sizeof(ksocket_t) * ncores, GFP_KERNEL);
	if (!sockets) {
		BLKDEV_ERRMSG;
		return -ENOMEM;
	}

	for (core=0; core<ncores; core++) {
		if ((ret = create_socket(&sockets[core])) != 0) {
			BLKDEV_ERRMSG;
			clear_sockets();
			return ret;
		}
	}

	return 0;
}

static void init_serv_addr(char *addr, int port)
{
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = inet_addr(addr);
	addr_srv.sin_port = htons(port);
	addr_len = sizeof(struct sockaddr_in);
}

static int get_serv_cores(void)
{
	ksocket_t socket;
	packet_t packet;
	int cores = 0;
	int ret;

	ret = create_socket(&socket);
	if (ret)
		return ret;

	memset(&packet, 0, sizeof(packet_t));
	packet.op = INIT;

	ret = ksend(socket, &packet, sizeof(packet_t), 0);
	if (ret <= 0) {
		BLKDEV_ERRMSG;
		return ret;
	}

	ret = krecv(socket, &cores, sizeof(int), 0);
	if (ret <= 0) {
		BLKDEV_ERRMSG;
		return ret;
	}

	clear_socket(socket);

	return cores;
}

static int map_ctx_to_hctx(void)
{
	int ncpus = num_online_cpus();
	int ctx, hctx;

	hctx_id = kmalloc(sizeof(int) * ncpus, GFP_KERNEL);
	if (!hctx_id) {
		BLKDEV_ERRMSG;
		return -ENOMEM;
	}

	for (ctx = 0; ctx < ncpus; ctx++)
		for (hctx = 0; hctx < ncores; hctx++)
			hctx_id[ctx] = hctx;

	return 0;
}

static void clear_threads(struct task_struct **threads)
{
	int core;

	if (threads == NULL)
		return;

	for (core=0; core<ncores; core++) {
		if (threads[core] == NULL)
			continue;

		kthread_stop(threads[core]);
		threads[core] = NULL;
	}

	kfree(threads);
}

static struct task_struct **create_threads(void *fn)
{
	struct task_struct **threads;
	int core;

	threads = kmalloc(sizeof(struct task_struct *) * ncores, GFP_KERNEL);
	if (!threads) {
		BLKDEV_ERRMSG;
		return NULL;
	}

	for (core=0; core<ncores; core++) {
		threads[core] = kthread_run(fn, (void *)core, name);
		if (IS_ERR(threads[core])) {
			clear_threads(threads);
			return NULL;
		}
	}

	return threads;
}

static void clear_sqs(void)
{
	struct llist_node *node;
	entry_t *next;
	int core;

	for (core = 0; core < ncores; core++) {
		while (!llist_empty(&sqs[core])) {
			node = llist_del_first(&sqs[core]);
			next = llist_entry(node, entry_t, node);
			kfree(next);
		}
	}

	kfree(sqs);
}

static int create_sqs(void)
{
	int core;

	sqs = kmalloc(sizeof(struct llist_head) * ncores, GFP_KERNEL);
	if (!sqs)
		return -ENOMEM;

	for (core = 0; core < ncores; core++)
		init_llist_head(&sqs[core]);

	return 0;
}

static int blkdev_alloc_buffer(block_dev_t *dev)
{
	u64 size = 4;
	char unit = sz[strlen(sz) - 1];
	int ret = 0;

	if (unit == 'K' || unit == 'k') {
		sz[strlen(sz) - 1] = '\0';
		ret = kstrtoull(sz, 10, &size);
		size *= 1024;
	} else if (unit == 'M' || unit == 'm') {
		sz[strlen(sz) - 1] = '\0';
		ret = kstrtoull(sz, 10, &size);
		size *= 1024 * 1024;
	} else if (unit == 'G' || unit == 'g') {
		sz[strlen(sz) - 1] = '\0';
		ret = kstrtoull(sz, 10, &size);
		size *= 1024 * 1024 * 1024;
	} else if (unit >= '0' && unit <= '9') {
		ret = kstrtoull(sz, 10, &size);
	} else {
		size *= 1024 * 1024 * 1024;
	}

	if (ret)
		size = 1024 * 1024 * 1024;

	dev->capacity = size >> SECTOR_SHIFT;
	return 0;
}

static void blkdev_free_buffer(block_dev_t *dev)
{
	dev->capacity = 0;
}

static int blkdev_add_device(void)
{
	int ret = 0;
	struct gendisk *disk;
	struct request_queue *q;
	block_dev_t *dev = kzalloc(sizeof(block_dev_t), GFP_KERNEL);
	if (dev == NULL) {
		BLKDEV_ERRMSG;
		return -ENOMEM;
	}
	blkdev_dev = dev;

	do {
		if ((ret = blkdev_alloc_buffer(dev)) != 0)
			break;

		dev->tag_set.cmd_size = sizeof(block_cmd_t);
		dev->tag_set.driver_data = dev;

		/* queue depth is 128 */
		q = blk_mq_init_sq_queue(&dev->tag_set, &mq_ops, 128,
				BLK_MQ_F_SHOULD_MERGE);
		if (IS_ERR(q)) {
			ret = PTR_ERR(q);
			BLKDEV_ERRMSG;
			break;
		}
		dev->queue = q;
		dev->queue->queuedata = dev;

		/* minor is 1 */
		if ((disk = alloc_disk(1)) == NULL) {
			BLKDEV_ERRMSG;
			ret = -ENOMEM;
			break;
		}

		/* only one partition */
		disk->flags |= GENHD_FL_NO_PART_SCAN;
		disk->flags |= GENHD_FL_REMOVABLE;
		disk->major = blkdev_major;
		disk->first_minor = 0;
		disk->fops = &blk_fops;
		disk->private_data = dev;
		disk->queue = dev->queue;
		sprintf(disk->disk_name, "%s%d", name, 0);
		set_capacity(disk, dev->capacity);
		dev->gdisk = disk;

		add_disk(disk);
	} while (false);

	if (ret) {
		blkdev_remove_device();
		BLKDEV_ERRMSG;
	}
	return ret;
}

static void blkdev_remove_device(void)
{
	block_dev_t *dev = blkdev_dev;

	if (!dev)
		return;

	if (dev->gdisk)
		del_gendisk(dev->gdisk);

	if (dev->queue) {
		blk_cleanup_queue(dev->queue);
		dev->queue = NULL;
	}

	if (dev->tag_set.tags)
		blk_mq_free_tag_set(&dev->tag_set);

	if (dev->gdisk) {
		put_disk(dev->gdisk);
		dev->gdisk = NULL;
	}

	blkdev_free_buffer(dev);
	kfree(dev);
	blkdev_dev = NULL;
}

static int __init blkdev_init(void)
{
	int ret;

	init_serv_addr(servaddr, servport);
	ncores = get_serv_cores();

	if ((ret = map_ctx_to_hctx()) != 0)
		goto err_mapping;

	if ((ret = create_sockets()) != 0)
		goto err_socket;

	if ((ret = create_sqs()) != 0)
		goto err_sqs;

	if ((cq_threads = create_threads(blkdev_completion)) == NULL) {
		ret = -EFAULT;
		goto err_cq;
	}

	if ((sq_threads = create_threads(blkdev_submission)) == NULL) {
		ret = -EFAULT;
		goto err_sq;
	}

	blkdev_major = register_blkdev(blkdev_major, name);
	if (blkdev_major <= 0) {
		BLKDEV_ERRMSG;
		ret = -EBUSY;
		goto err_register;
	}

	if ((ret = blkdev_add_device()) != 0)
		goto err_adddev;

	printk("%s init\n - size: %llu bytes \n - server address: %s:%d \n"
			" - number of ctx: %d \n - number of hctx: %d \n",
			name, blkdev_dev->capacity << SECTOR_SHIFT,
			servaddr, servport, num_online_cpus(), ncores);

	return 0;

err_adddev:
	unregister_blkdev(blkdev_major, name);
err_register:
	clear_threads(sq_threads);
err_sq:
	clear_threads(cq_threads);
err_cq:
	clear_sqs();
err_sqs:
	clear_sockets();
err_socket:
	kfree(hctx_id);
err_mapping:
	return ret;
}

static void __exit blkdev_exit(void)
{
	blkdev_remove_device();

	if (blkdev_major > 0)
		unregister_blkdev(blkdev_major, name);

	clear_threads(sq_threads);
	clear_threads(cq_threads);
	clear_sockets();
	clear_sqs();
	kfree(hctx_id);

	printk("%s exit\n", name);
}

module_init(blkdev_init);
module_exit(blkdev_exit);
MODULE_LICENSE("GPL");
