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
#include <linux/llist.h>
#include <linux/kthread.h>

#define BLKDEV_DEBUG	0

#define BLKDEV_ERRMSG printk(KERN_ERR "[%s %d] %s call %p \n", \
				__FILE__, __LINE__, __FUNCTION__, __builtin_return_address(0))

typedef struct {
	unsigned int op;
	u16 hwq;
	loff_t offset;
	u64 size;
	u16 tag;
} packet_t;

typedef struct {
	struct llist_node llnode;
	struct request *rq;
	packet_t packet;
} qentry_t;

static LLIST_HEAD(sq); // submission queue
static spinlock_t sq_lock;

static struct task_struct **threads;
static ksocket_t *sockets;

/* Module parameters */
static struct sockaddr_in addr_srv;
static int addr_len;
static int blkdev_major = 0;
static block_dev_t *blkdev_dev = NULL;

int send_metadata(ksocket_t socket, packet_t *packet)
{
	int flags = op_is_write(packet->op) ? MSG_MORE : MSG_EOR;
	int len;

	len = ksend(socket, packet, sizeof(packet_t), flags);
	if (len <= 0)
		BLKDEV_ERRMSG;

#if BLKDEV_DEBUG
	printk("send packet: op(%u) offset(%llu) size(%llu) tag(%u)\n",
			packet->op, packet->offset, packet->size, packet->tag);
#endif

	return len;
}

int send_data(ksocket_t socket, packet_t *packet, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int remains = packet->size;
	int len;

	rq_for_each_segment(bvec, rq, iter) {
		unsigned long b_len = bvec.bv_len;
		void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;
		int flags = (remains - b_len) ? MSG_MORE : MSG_EOR;

		len = ksend(socket, b_buf, b_len, flags);
		if (len <= 0) {
			BLKDEV_ERRMSG;
			return len;
		}

		remains -= len;
	}

	return len;
}

ssize_t recv_metadata(packet_t *packet, ksocket_t socket)
{
	return krecv(socket, packet, sizeof(packet_t), MSG_WAITALL);
}

ssize_t recv_data(packet_t *packet, ksocket_t socket, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int len = packet->size;

	rq_for_each_segment(bvec, rq, iter) {
		unsigned long b_len = bvec.bv_len;
		void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;
		len = krecv(socket, b_buf, b_len, MSG_WAITALL);

		if (len != b_len) {
			BLKDEV_ERRMSG;
			break;
		}
	}

	return len;
}

static void blkdev_work(void *data)
{
	struct llist_node *node = NULL;
	qentry_t *next;
	ksocket_t socket = data;
	packet_t packet;
	struct request *rq;

	while (!kthread_should_stop()) {
		spin_lock(&sq_lock);
		node = llist_del_first(&sq);
		spin_unlock(&sq_lock);

		if (!node)
			goto skip;

		next = llist_entry(node, qentry_t, llnode);

		send_metadata(socket, &(next->packet));
		if (op_is_write(rq_data_dir(next->rq)))
			send_data(socket, &(next->packet), next->rq);

		kfree(next);

		if (recv_metadata(&packet, socket) != sizeof(packet_t)) {
			BLKDEV_ERRMSG;
			goto skip;
		}

		rq = blk_mq_tag_to_rq(blkdev_dev->tag_set.tags[packet.hwq], packet.tag);
		if (!rq) {
			BLKDEV_ERRMSG;
			goto skip;
		}

		if (!op_is_write(packet.op) && recv_data(&packet, socket, rq) <= 0) {
			BLKDEV_ERRMSG;
			goto skip;
		}

		blk_mq_complete_request(rq);
skip:
		io_schedule();
	}
	do_exit(0);
}

static qentry_t *create_entry(struct request *rq, int hctx_idx)
{
	qentry_t *entry;
	packet_t *packet;

	entry = kmalloc(sizeof(qentry_t), GFP_KERNEL);
	if (!entry) {
		BLKDEV_ERRMSG;
		return NULL;
	}

	entry->rq = rq;

	packet = &(entry->packet);

	packet->op = rq_data_dir(rq);
	packet->hwq = hctx_idx;
	packet->offset = blk_rq_pos(rq) << SECTOR_SHIFT;
	packet->tag = rq->tag;
	packet->size = blk_rq_bytes(rq);

	return entry;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	qentry_t *entry;

	blk_mq_start_request(rq);

	entry = create_entry(rq, hctx->queue_num);
	if (!entry)
		return BLK_STS_IOERR;

	llist_add(&entry->llnode, &sq);

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

static void init_serv_addr(char *addr, int port)
{
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = inet_addr(addr);
	addr_srv.sin_port = htons(port);
	addr_len = sizeof(struct sockaddr_in);
}

static void clear_socket(ksocket_t socket)
{
	if (socket) {
		kshutdown(socket, SHUT_RDWR);
		kclose(socket);
	}
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

	ret = ksend(socket, &packet, sizeof(packet_t), MSG_EOR);
	if (ret <= 0) {
		BLKDEV_ERRMSG;
		return ret;
	}

	ret = krecv(socket, &cores, sizeof(int), MSG_WAITALL);
	if (ret <= 0) {
		BLKDEV_ERRMSG;
		return ret;
	}

	clear_socket(socket);

	return cores;
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

static struct task_struct **create_threads(void *fn, const char *tname)
{
	struct task_struct **threads;
	int core;

	threads = kmalloc(sizeof(struct task_struct *) * ncores, GFP_KERNEL);
	if (!threads) {
		BLKDEV_ERRMSG;
		return NULL;
	}

	for (core=0; core<ncores; core++) {
		threads[core] = kthread_run(fn, (void *)sockets[core], tname);
		if (IS_ERR(threads[core])) {
			clear_threads(threads);
			return NULL;
		}
	}

	return threads;
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

		dev->tag_set.ops = &mq_ops;
		dev->tag_set.nr_hw_queues = ncores;
		dev->tag_set.queue_depth = 128;
		dev->tag_set.numa_node = NUMA_NO_NODE; /* TODO */
		dev->tag_set.cmd_size = sizeof(block_cmd_t);
		dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
		dev->tag_set.driver_data = dev;

		ret = blk_mq_alloc_tag_set(&dev->tag_set);
		if (ret) {
			BLKDEV_ERRMSG;
			break;
		}

		q = blk_mq_init_queue(&dev->tag_set);
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

	if ((ret = create_sockets()) != 0)
		goto err_socket;

	spin_lock_init(&sq_lock);

	if ((threads = create_threads(blkdev_work, "blkdev")) == NULL) {
		ret = -EFAULT;
		goto err_threads;
	}

	blkdev_major = register_blkdev(blkdev_major, name);
	if (blkdev_major <= 0) {
		BLKDEV_ERRMSG;
		ret = -EBUSY;
		goto err_register;
	}

	if ((ret = blkdev_add_device()) != 0)
		goto err_adddev;

	printk("%s init\n - size:%llu \n - server address: %s:%d \n - %d threads\n",
			name, blkdev_dev->capacity << SECTOR_SHIFT,
			servaddr, servport, ncores);

	return 0;

err_adddev:
	unregister_blkdev(blkdev_major, name);
err_register:
	clear_threads(threads);
err_threads:
	clear_sockets();
err_socket:
	return ret;
}

static void __exit blkdev_exit(void)
{
	struct llist_node *node = NULL;
	qentry_t *next;

	clear_threads(threads);
	clear_sockets();

	while (!llist_empty(&sq)) {
		node = llist_del_first(&sq);
		next = llist_entry(node, qentry_t, llnode);
		kfree(next);
	}

	blkdev_remove_device();

	if (blkdev_major > 0)
		unregister_blkdev(blkdev_major, name);

	printk("%s exit\n", name);
}

module_init(blkdev_init);
module_exit(blkdev_exit);
MODULE_LICENSE("GPL");
