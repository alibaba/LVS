#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/miscdevice.h>

#include "queue.h"

#define TLOCK_INIT_FILE_NUM	0
#define TLOCK_LOCK_NUM		1
#define TLOCK_UNLOCK_NUM	2

#define TLOCK_TYPE		0xd3

#define TLOCK_INIT_FILE	0xd300
#define TLOCK_LOCK	0xd301
#define TLOCK_UNLOCK	0xd302
#define TLOCK_STAT	0xd303

#define MAX_FILE_PER_TASK	128

#define TLOCK_PID_MASK		0x001fffff
#define TLOCK_COUNT_MASK	0x7fe00000

#define __wait_event_exclusive_interruptible_timeout(wq, condition, ret)	\
do {										\
	DEFINE_WAIT(__wait);							\
	for(;;) {								\
		prepare_to_wait_exclusive(					\
			&wq, &__wait, TASK_INTERRUPTIBLE);			\
		if (condition)							\
			break;							\
		if(!signal_pending(current)) {					\
			ret = schedule_timeout(ret);				\
			if (ret)						\
				continue;					\
			break;							\
		}								\
		ret = -ERESTARTSYS;						\
		break;								\
	}									\
	finish_wait(&wq, &wait);						\
} while(0)

#define __wait_interruptible(wq, ret)						\
do {										\
	DEFINE_WAIT(__wait);							\
	prepare_to_wait_exclusive(&wq, &__wait, TASK_INTERRUPTIBLE);		\
	if (!signal_pending(current))						\
		ret = schedule_timeout(ret);					\
	finish_wait(&wq, &__wait);						\
} while(0)

#define wait_event_exclusive_interruptible_timeout(wq, condition, timeout)	\
({										\
	long __ret = timeout;							\
	if (!(condition))							\
		__wait_event_exclusive_interruptible_timeout(			\
			wq, condition, __ret);					\
	ret;									\
})

#define wait_exclusive_interruptible_timeout(wq, timeout)			\
({										\
	long __ret = timeout;							\
	__wait_interruptible(wq, __ret);					\
	__ret;									\
})

MODULE_LICENSE("GPL");
MODULE_AUTHOR("donghao");
MODULE_DESCRIPTION("tlock device driver");

typedef struct tlock_args {
	int fd;
	int align1;
	uint64_t offset;
	uint64_t addr;
} tlock_args_t;

typedef struct wait_queue {
	wait_queue_head_t	waitq_outer;
	spinlock_t		spin_lock;
	int			sig_flag;
} tlock_wait_queue;

typedef struct tlock_file {
	MLIST_ENTRY(tlock_file)	link;
	MLIST_HEAD(,tlock_task)	task_head;
	struct inode		*inode;
	size_t			task_num;
	size_t			lock_num;
	tlock_wait_queue	**tlock_waitq;
	spinlock_t		spin_lock;
} tlock_file_t;

typedef struct tlock_task {
	MLIST_ENTRY(tlock_task)	link;
	pid_t			pid;
	pid_t			leader_pid;
	size_t			offset;
	tlock_file_t		**lock_file_array;
	size_t			filep_used_num;
	size_t			filep_num;
} tlock_task_t;

MLIST_HEAD(,tlock_file) g_file_list = {NULL};
DECLARE_MUTEX(g_sema_file);

MLIST_HEAD(, tlock_task) g_task_list = {NULL};
DECLARE_MUTEX(g_sema_task);

#define TASK_BUCKET_SHIFT	10
#define TASK_BUCKET_NUM		(1 << TASK_BUCKET_SHIFT)
#define TASK_BUCKET_MARK	(TASK_BUCKET_NUM - 1)

typedef struct tlock_hash_task {
	MLIST_ENTRY(tlock_hash_task) link;
	tlock_task_t *ptr_tlock_task;
} tlock_hash_task_t;

MLIST_HEAD(, tlock_hash_task) g_tlock_task_htable[TASK_BUCKET_NUM] = {{NULL}};

inline void add_file_to_task(tlock_task_t* task, tlock_file_t* file);
inline tlock_task_t* alloc_tlock_task(tlock_file_t* file, size_t offset);
inline tlock_hash_task_t* alloc_tlock_hash_task(tlock_task_t * ptr_tlock_task);
inline void free_tlock_task(tlock_task_t* task);
inline tlock_task_t* find_tlock_task(struct task_struct* ts);
inline tlock_file_t* alloc_tlock_file(struct inode* node, size_t lock_num);
inline void free_tlock_file(tlock_file_t* file);
inline void update_list(tlock_args_t* args, struct inode *node);
inline int lock_list(tlock_args_t* args, struct inode* node);
inline void unlock_list(tlock_args_t* args, struct inode *node);
inline int lock_in_file(tlock_file_t* file, size_t offset, caddr_t addr);
inline int unlock_in_file(tlock_file_t* file, size_t offset, caddr_t addr);
inline tlock_file_t* find_file_in_list(struct inode* node);

/* for tlock stat tool */
static void traverse_tlock_task(void)
{
	int i;
	tlock_task_t *task;
	tlock_hash_task_t *htask;

	printk("begin-- print tlock task info...............\n\n");
	down(&g_sema_task);

	printk("begin-- print tlock task....................\n");
	task = MLIST_FIRST(&g_task_list);
	while(task) {
		printk("task pid = %d, task thread_group leader = %d\n", task->pid, task->leader_pid);
		task = MLIST_NEXT(task, link);
	}
	printk("end--   print tlock task....................\n\n");

	printk("begin-- print tlock hash task...............\n");
	for(i = 0; i < TASK_BUCKET_NUM; i++) {
		htask = MLIST_FIRST(&g_tlock_task_htable[i]);
		while(htask) {
			printk("bucket number = %d,hash_table task leader pid = %d\n", i, htask->ptr_tlock_task->leader_pid);
			htask = MLIST_NEXT(htask, link);
		}
	}

	printk("end--   print tlock hash task...............\n\n");

	printk("end--   print tlock task info...............\n");

	up(&g_sema_task);
}

int tlock_ioctl(struct inode *inode, struct file *dev_file, unsigned int cmd, unsigned long data)
{
	tlock_args_t args;
	struct inode *node;
	struct file *file;
	int fput_needed;
	int ret = 0;

	if (cmd == TLOCK_STAT) {
		traverse_tlock_task();
		return 0;
	}

	if (copy_from_user(&args, (void *)data, sizeof(tlock_args_t)))
		return -EFAULT;

	file = tlock_fget_light(args.fd, &fput_needed);
	if (!file)
		return -EFAULT;

	node = file->f_dentry->d_inode;
	if (!node) {
		tlock_fput_light(file, fput_needed);
		return -EFAULT;
	}

	switch(cmd) {
	case TLOCK_INIT_FILE:
		down(&g_sema_task);
		down(&g_sema_file);
		update_list(&args, node);
		up(&g_sema_file);
		up(&g_sema_task);
		break;
	case TLOCK_LOCK:
		ret = lock_list(&args, node);
		break;
	case TLOCK_UNLOCK:
		unlock_list(&args, node);
		break;
	default:
		printk(KERN_ALERT "unknow cmd %d in %s:%d", cmd, __func__, __LINE__);
		ret = -EINVAL;
		break;
	}

	tlock_fput_light(file, fput_needed);
	return ret;
}

int tlock_flush(struct file *dev_file, fl_owner_t lock)
{
	tlock_task_t *old_task, *task;
	tlock_hash_task_t *old_htask, *htask;
	int ret = -EFAULT;

	down(&g_sema_task);
	down(&g_sema_file);

	if (MLIST_EMPTY(&g_task_list))
		goto out;

	task = MLIST_FIRST(&g_task_list);
	while(task) {
		if (task->pid == current->pid ||
		    task->leader_pid == current->tgid) {
			htask = MLIST_FIRST( &g_tlock_task_htable[
					TASK_BUCKET_MARK & task->leader_pid]);
			while(htask) {
				if (htask->ptr_tlock_task->leader_pid ==
				    task->leader_pid) {
					old_htask = htask;
					htask = MLIST_NEXT(htask, link);
					MLIST_REMOVE(old_htask, link);
					kfree(old_htask);
					if (!htask)
						break;
				}
				htask = MLIST_NEXT(htask, link);
			}

			old_task = task;
			free_tlock_task(task);

			task = MLIST_NEXT(task, link);
			MLIST_REMOVE(old_task, link);
			kfree(old_task);

			if (!task)
				break;
		}
		task = MLIST_NEXT(task, link);
	}
	ret = 0;
out:
	up(&g_sema_file);
	up(&g_sema_task);
	return ret;

}

tlock_task_t * alloc_tlock_task(tlock_file_t *file, size_t offset)
{
	tlock_task_t *task;

	task = kmalloc(sizeof(tlock_task_t), GFP_KERNEL);
	if (unlikely(!task)) {
		printk(KERN_ALERT "nomem for task\n");
		goto out;
	}

	task->pid = current->pid;
	task->leader_pid = current->tgid;
	task->offset = offset;
	task->lock_file_array = kmalloc(sizeof(tlock_file_t *) * MAX_FILE_PER_TASK, GFP_KERNEL);
	if (unlikely(!task->lock_file_array)) {
		printk(KERN_ALERT "nomem for lock_file_array\n");
		kfree(task);
		task = NULL;
		goto out;
	}
	task->filep_num = MAX_FILE_PER_TASK;
	task->filep_used_num = 0;
out:
	return task;
}

tlock_hash_task_t * alloc_tlock_hash_task(tlock_task_t *ptr_tlock_task)
{
	tlock_hash_task_t *task;

	task = kmalloc(sizeof(tlock_hash_task_t), GFP_KERNEL);
	if (task)
		task->ptr_tlock_task = ptr_tlock_task;
	else
		printk(KERN_ALERT "nomem for hash_task\n");

	return task;
}

tlock_task_t * find_tlock_task(struct task_struct *ts)
{
	tlock_task_t *ret_task = NULL;
	tlock_hash_task_t *htask;

	down(&g_sema_task);

	htask = MLIST_FIRST(&g_tlock_task_htable[TASK_BUCKET_MARK & ts->tgid]);
	while (htask && (htask->ptr_tlock_task->leader_pid != ts->tgid))
		htask = MLIST_NEXT(htask, link);

	if (htask)
		ret_task = htask->ptr_tlock_task;

	up(&g_sema_task);
	return ret_task;
}

void free_tlock_task(tlock_task_t *task)
{
	int i, lock_pos;
	tlock_file_t *file;
	tlock_wait_queue *wait_queue;

	for(i = 0; i < task->filep_used_num; i++) {
		file = task->lock_file_array[i];
		if (!file)
			continue;

		file->task_num--;
		if (file->task_num <= 0) {
			MLIST_REMOVE(file, link);
			free_tlock_file(file);
			continue;
		}

		for (lock_pos = 0;
		     lock_pos < file->lock_num;
		     lock_pos ++) {
			wait_queue = file->tlock_waitq[lock_pos];
			if (wait_queue)
				wake_up_interruptible_sync(
					&wait_queue->waitq_outer);
		}
	}
	kfree(task->lock_file_array);
}

tlock_file_t *alloc_tlock_file(struct inode *node, size_t lock_num)
{
	size_t i;
	tlock_file_t *file;

	file = kmalloc(sizeof(tlock_file_t), GFP_KERNEL);
	if (unlikely(!file)) {
		printk(KERN_ALERT "nomem for file\n");
		goto out;
	}

	file->task_num = 0;
	file->inode = node;
	file->lock_num = lock_num;
	spin_lock_init(&file->spin_lock);

	file->tlock_waitq = kmalloc(sizeof(tlock_wait_queue *) * lock_num,
				    GFP_KERNEL);
	if (unlikely(!file->tlock_waitq)) {
		printk(KERN_ALERT "nomen for waitq\n");
		kfree(file);
		file = NULL;
		goto out;
	}

	for (i = 0; i < lock_num; i++)
		file->tlock_waitq[i] = NULL;
	MLIST_INSERT_HEAD(&g_file_list, file, link);

out:
	return file;
}

void free_tlock_file(tlock_file_t *file)
{
	size_t i;
	tlock_wait_queue *wait_queue;

	for(i = 0; i < file->lock_num; i++) {
		wait_queue = file->tlock_waitq[i];
		if (wait_queue)
			kfree(wait_queue);
	}

	kfree(file->tlock_waitq);
	kfree(file);
}

void update_list(tlock_args_t *args, struct inode *node)
{
	size_t i;
	int fill_node = 0;
	int error;
	int *addr;
	tlock_task_t *task;
	tlock_hash_task_t *htask;
	tlock_file_t *file;

	file = find_file_in_list(node);
	if (!file) {
		file = alloc_tlock_file(node, args->offset);
		if (!file) {
			printk(KERN_ALERT "file struct NULL\n");
			return;
		}
		addr = (int *)args->addr;
		for (i = 0; i < args->offset; i++) {
			error = copy_to_user(addr, &fill_node, sizeof(int));
			addr++;
		}
	}

	MLIST_FOREACH(task, &g_task_list, link) {
		if (task->pid == current->pid) {
			add_file_to_task(task, file);
			return;
		}
	}

	task = alloc_tlock_task(file, args->offset);
	if (!task) {
		printk(KERN_ALERT "task struct NULL\n");
		return;
	}

	htask = alloc_tlock_hash_task(task);
	if (!htask) {
		printk(KERN_ALERT "hash_task struct NULL\n");
		free_tlock_task(task);
		return;
	}

	add_file_to_task(task, file);

	MLIST_INSERT_HEAD(&g_task_list, task, link);
	MLIST_INSERT_HEAD(&g_tlock_task_htable[current->tgid & TASK_BUCKET_MARK], htask, link);
}

void add_file_to_task(tlock_task_t *task, tlock_file_t *file)
{
	int i = 0;
	for (i = 0; i < task->filep_used_num; i++) {
		if (file == task->lock_file_array[i])
			return;
	}

	if (task->filep_used_num >= MAX_FILE_PER_TASK) {
		printk(KERN_ALERT "lock_file_arry full, add file to task failed.\n");
		return;
	}
	task->lock_file_array[task->filep_used_num] = file;
	task->filep_used_num ++;
	file->task_num ++;
}

int lock_list(tlock_args_t *args, struct inode *node)
{
	tlock_file_t *file = find_file_in_list(node);
	int ret = -EINVAL;

	if (unlikely(!file))
		goto out;

	if (args->offset >= file->lock_num) {
		printk(KERN_ALERT "offset too large\n");
		goto out;
	}

	ret = lock_in_file(file, args->offset, (caddr_t)args->addr);
out:
	return ret;
}

void unlock_list(tlock_args_t *args, struct inode *node)
{
	tlock_file_t *file = find_file_in_list(node);

	if (!file)
		return;

	if (args->offset >= file->lock_num)
		return;

	unlock_in_file(file, args->offset, (caddr_t)args->addr);
}


tlock_file_t * find_file_in_list(struct inode *node)
{
	tlock_file_t *file = NULL;

	MLIST_FOREACH(file, &g_file_list, link) {
		if (file && file->inode == node)
			break;
	}

	if (MLIST_EMPTY(&g_file_list) || !file || file->inode != node)
		return NULL;

	return file;
}

int lock_in_file(tlock_file_t *file, size_t offset, caddr_t addr)
{
	tlock_wait_queue *wait_queue;
	pid_t cur_pid;
	struct task_struct * pts;
	tlock_task_t *ptlts = NULL;
	int mutex;
	int ret = 0;

	wait_queue = file->tlock_waitq[offset];
	if (likely(wait_queue))
		goto lock_wait_pid;

	spin_lock(&file->spin_lock);
	wait_queue = kmalloc(sizeof(tlock_wait_queue), GFP_KERNEL);
	if (unlikely(!wait_queue)) {
		spin_unlock(&file->spin_lock);
		printk(KERN_ALERT "nomemory for waitq\n");
		ret = -ENOMEM;
		goto out;
	}

	file->tlock_waitq[offset] = wait_queue;
	init_waitqueue_head(&(wait_queue->waitq_outer));
	spin_lock_init(&(wait_queue->spin_lock));
	wait_queue->sig_flag = 0;
	spin_unlock(&file->spin_lock);

lock_wait_pid:
	ret = copy_from_user(&mutex, (void *)addr, sizeof(int));
	if (unlikely(ret))
		goto out;

	if ((mutex & (TLOCK_PID_MASK | TLOCK_COUNT_MASK)) == 0)
		goto out;

	ret = wait_exclusive_interruptible_timeout(
				wait_queue->waitq_outer, HZ);
	if (unlikely(ret))
		goto out;

	ret = copy_from_user(&mutex, (void *)addr, sizeof(int));
	if (unlikely(ret))
		goto out;

	cur_pid = (mutex & TLOCK_PID_MASK);

	read_lock_tasklist();
	pts = find_task_by_pid_ns(cur_pid, &init_pid_ns);
	read_unlock_tasklist();

	if (pts)
		ptlts = find_tlock_task(pts);
	if (!pts || !ptlts)
		ret = cur_pid;
out:
	return ret;
}

int unlock_in_file(tlock_file_t *file, size_t offset, caddr_t addr)
{
	tlock_wait_queue *wait_queue = NULL;

	wait_queue = file->tlock_waitq[offset];
	if (wait_queue)
		wake_up_interruptible_sync(&wait_queue->waitq_outer);
	return 0;
}

long tlock_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return tlock_ioctl(NULL, NULL, cmd, arg);
}

struct file_operations tlock_fops = {
	.owner = THIS_MODULE,
	.ioctl = tlock_ioctl,
	.compat_ioctl = tlock_compat_ioctl,
	.flush = tlock_flush
};

static struct miscdevice tlock_dev = {
	MISC_DYNAMIC_MINOR,
	"tlock",
	&tlock_fops
};

static int tlock_kern_init(void)
{
	misc_register(&tlock_dev);
	printk(KERN_ALERT "tlock init\n");
	return 0;
}


static void tlock_kern_exit(void)
{
	misc_deregister(&tlock_dev);
	printk(KERN_ALERT "tlock exit\n");
}



module_init(tlock_kern_init);
module_exit(tlock_kern_exit);
