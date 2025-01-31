// [[ reference ]]
// - name: [Linux Kernel 5] Block Device Driver Example
// - author: pr0gr4m
// - link:
// https://pr0gr4m.tistory.com/entry/Linux-Kernel-5-Block-Device-Driver-Example
#ifndef __BLKDEV_H__
#define __BLKDEV_H__

#include <linux/blk-mq.h>
#include <linux/types.h>
#include <linux/moduleparam.h>

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif

#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define INIT		-1

typedef struct block_cmd {
} block_cmd_t;

typedef struct block_dev {
  sector_t capacity;
  u8 *data;
  atomic_t open_counter;

  struct blk_mq_tag_set tag_set;
  struct request_queue *queue;
  struct gendisk *gdisk;
} block_dev_t;

static char *servaddr = "127.0.0.1";
module_param(servaddr, charp, 0);

static int servport = 4444;
module_param(servport, int, 0);

static char *name = "socketdev";
module_param(name, charp, 0);

static char *sz = "1GB";
module_param(sz, charp, 0);

static int ncores = 4;

static int blkdev_alloc_buffer(block_dev_t *dev);
static void blkdev_free_buffer(block_dev_t *dev);
static int blkdev_add_device(void);
static void blkdev_remove_device(void);

#endif
