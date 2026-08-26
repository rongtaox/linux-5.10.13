// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */

#include <linux/init.h>
#include <linux/namei.h>
#include <linux/pid_namespace.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/filter.h>
#include <linux/btf_ids.h>

struct bpf_iter_seq_task_common {
	struct pid_namespace *ns;
};

struct bpf_iter_seq_task_info {
	/* The first field must be struct bpf_iter_seq_task_common.
	 * this is assumed by {init, fini}_seq_pidns() callback functions.
	 */
	struct bpf_iter_seq_task_common common;
	u32 tid;
};

static struct task_struct *task_seq_get_next(struct pid_namespace *ns,
					     u32 *tid,
					     bool skip_if_dup_files)
{
	struct task_struct *task = NULL;
	struct pid *pid;

	rcu_read_lock();
retry:
	pid = find_ge_pid(*tid, ns);
	if (pid) {
		*tid = pid_nr_ns(pid, ns);
		task = get_pid_task(pid, PIDTYPE_PID);
		if (!task) {
			++*tid;
			goto retry;
		} else if (skip_if_dup_files && task->tgid != task->pid &&
			   task->files == task->group_leader->files) {
			put_task_struct(task);
			task = NULL;
			++*tid;
			goto retry;
		}
	}
	rcu_read_unlock();

	return task;
}

static void *task_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_task_info *info = seq->private;
	struct task_struct *task;

	task = task_seq_get_next(info->common.ns, &info->tid, false);
	if (!task)
		return NULL;

	if (*pos == 0)
		++*pos;
	return task;
}

static void *task_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_task_info *info = seq->private;
	struct task_struct *task;

	++*pos;
	++info->tid;
	put_task_struct((struct task_struct *)v);
	task = task_seq_get_next(info->common.ns, &info->tid, false);
	if (!task)
		return NULL;

	return task;
}

struct bpf_iter__task {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct task_struct *, task);
};

(task, struct bpf_iter_meta *meta, struct task_struct *task)

static int __task_seq_show(struct seq_file *seq, struct task_struct *task,
			   bool in_stop)
{
	struct bpf_iter_meta meta;
	struct bpf_iter__task ctx;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	meta.seq = seq;
	ctx.meta = &meta;
	ctx.task = task;
	return bpf_iter_run_prog(prog, &ctx);
}

static int task_seq_show(struct seq_file *seq, void *v)
{
	return __task_seq_show(seq, v, false);
}

static void task_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void)__task_seq_show(seq, v, true);
	else
		put_task_struct((struct task_struct *)v);
}

static const struct seq_operations task_seq_ops = {
	.start	= task_seq_start,
	.next	= task_seq_next,
	.stop	= task_seq_stop,
	.show	= task_seq_show,
};

struct bpf_iter_seq_task_file_info {
	/* The first field must be struct bpf_iter_seq_task_common.
	 * this is assumed by {init, fini}_seq_pidns() callback functions.
	 */
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct files_struct *files;
	u32 tid;
	u32 fd;
};

/**
 * @brief
 *
 * @param info
 * @return struct file*
 */
static struct file *
task_file_seq_get_next(struct bpf_iter_seq_task_file_info *info)
{
	struct pid_namespace *ns = info->common.ns;
	u32 curr_tid = info->tid, max_fds;
	struct files_struct *curr_files;
	struct task_struct *curr_task;
	int curr_fd = info->fd;

	/* If this function returns a non-NULL file object,
	 * it held a reference to the task/files_struct/file.
	 * Otherwise, it does not hold any reference.
	 */
again:
	if (info->task) {
		curr_task = info->task;
		curr_files = info->files;
		curr_fd = info->fd;
	} else {
		curr_task = task_seq_get_next(ns, &curr_tid, true);
		if (!curr_task) {
			info->task = NULL;
			info->files = NULL;
			info->tid = curr_tid;
			return NULL;
		}

		curr_files = get_files_struct(curr_task);
		if (!curr_files) {
			put_task_struct(curr_task);
			curr_tid = curr_tid + 1;
			info->fd = 0;
			goto again;
		}

		info->files = curr_files;
		info->task = curr_task;
		if (curr_tid == info->tid) {
			curr_fd = info->fd;
		} else {
			info->tid = curr_tid;
			curr_fd = 0;
		}
	}

	rcu_read_lock();
	max_fds = files_fdtable(curr_files)->max_fds;
	for (; curr_fd < max_fds; curr_fd++) {
		struct file *f;

		f = fcheck_files(curr_files, curr_fd);
		if (!f)
			continue;
		if (!get_file_rcu(f))
			continue;

		/* set info->fd */
		info->fd = curr_fd;
		rcu_read_unlock();
		return f;
	}

	/* the current task is done, go to the next task */
	rcu_read_unlock();
	put_files_struct(curr_files);
	put_task_struct(curr_task);
	info->task = NULL;
	info->files = NULL;
	info->fd = 0;
	curr_tid = ++(info->tid);
	goto again;
}

static void *task_file_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;
	struct file *file;

	info->task = NULL;
	info->files = NULL;
	file = task_file_seq_get_next(info);
	if (file && *pos == 0)
		++*pos;

	return file;
}

static void *task_file_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;

	++*pos;
	++info->fd;
	fput((struct file *)v);
	return task_file_seq_get_next(info);
}

struct bpf_iter__task_file {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct task_struct *, task);
	u32 fd __aligned(8);
	__bpf_md_ptr(struct file *, file);
};

(task_file, struct bpf_iter_meta *meta,
		     struct task_struct *task, u32 fd,
		     struct file *file)

#if 1 /* 上面展开为 */
extern int bpf_iter_task_file(struct bpf_iter_meta *meta,
			struct task_struct *task, u32 fd,
			struct file *file);
int __init bpf_iter_task_file(struct bpf_iter_meta *meta,
			struct task_struct *task, u32 fd,
			struct file *file) { return 0; }
#endif

static int __task_file_seq_show(struct seq_file *seq, struct file *file,
				bool in_stop)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;
	struct bpf_iter__task_file ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	ctx.meta = &meta;
	ctx.task = info->task;
	ctx.fd = info->fd;
	ctx.file = file;
	return bpf_iter_run_prog(prog, &ctx);
}

static int task_file_seq_show(struct seq_file *seq, void *v)
{
	return __task_file_seq_show(seq, v, false);
}

static void task_file_seq_stop(struct seq_file *seq, void *v)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;

	if (!v) {
		(void)__task_file_seq_show(seq, v, true);
	} else {
		fput((struct file *)v);
		put_files_struct(info->files);
		put_task_struct(info->task);
		info->files = NULL;
		info->task = NULL;
	}
}

static int init_seq_pidns(void *priv_data, struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_task_common *common = priv_data;

	common->ns = get_pid_ns(task_active_pid_ns(current));
	return 0;
}

static void fini_seq_pidns(void *priv_data)
{
	struct bpf_iter_seq_task_common *common = priv_data;

	put_pid_ns(common->ns);
}

static const struct seq_operations task_file_seq_ops = {
	.start	= task_file_seq_start,
	.next	= task_file_seq_next,
	.stop	= task_file_seq_stop,
	.show	= task_file_seq_show,
};

BTF_ID_LIST(btf_task_file_ids)
/**
 * @brief 添加 BTF？
 *
 */
BTF_ID(struct, task_struct)
BTF_ID(struct, file)

static const struct bpf_iter_seq_info task_seq_info = {
	.seq_ops		= &task_seq_ops,
	.init_seq_private	= init_seq_pidns,
	.fini_seq_private	= fini_seq_pidns,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_task_info),
};

static struct bpf_iter_reg task_reg_info = {
	.target			= "task",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__task, task),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &task_seq_info,
};

/**
 * @brief
 *
 */
static const struct bpf_iter_seq_info task_file_seq_info = {
	.seq_ops		= &task_file_seq_ops,
	.init_seq_private	= init_seq_pidns,
	.fini_seq_private	= fini_seq_pidns,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_task_file_info),
};

static struct bpf_iter_reg task_file_reg_info = {
	.target			= "task_file",
	.ctx_arg_info_size	= 2,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__task_file, task),
		  PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__task_file, file),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &task_file_seq_info,
};


__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
				      struct task_struct *task, u64 addr)
{
	struct bpf_iter_task_vma_kern *kit = (void *)it;
	int err;

	BUILD_BUG_ON(sizeof(struct bpf_iter_task_vma_kern) != sizeof(struct bpf_iter_task_vma));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_task_vma_kern) != __alignof__(struct bpf_iter_task_vma));

	if (!IS_ENABLED(CONFIG_PER_VMA_LOCK)) {
		kit->data = NULL;
		return -EOPNOTSUPP;
	}

	/*
	 * Reject irqs-disabled contexts including NMI. Operations used
	 * by _next() and _destroy() (vma_end_read, fput, bpf_iter_mmput_async)
	 * can take spinlocks with IRQs disabled (pi_lock, pool->lock).
	 * Running from NMI or from a tracepoint that fires with those
	 * locks held could deadlock.
	 */
	if (irqs_disabled()) {
		kit->data = NULL;
		return -EBUSY;
	}

	/* is_iter_reg_valid_uninit guarantees that kit hasn't been initialized
	 * before, so non-NULL kit->data doesn't point to previously
	 * bpf_mem_alloc'd bpf_iter_task_vma_kern_data
	 */
	kit->data = bpf_mem_alloc(&bpf_global_ma, sizeof(struct bpf_iter_task_vma_kern_data));
	if (!kit->data)
		return -ENOMEM;

	kit->data->task = get_task_struct(task);
	/*
	 * Safely read task->mm and acquire an mm reference.
	 *
	 * Cannot use get_task_mm() because its task_lock() is a
	 * blocking spin_lock that would deadlock if the target task
	 * already holds alloc_lock on this CPU (e.g. a softirq BPF
	 * program iterating a task interrupted while holding its
	 * alloc_lock).
	 */
	if (!spin_trylock(&task->alloc_lock)) {
		err = -EBUSY;
		goto err_cleanup_iter;
	}
	kit->data->mm = task->mm;
	if (kit->data->mm && !(task->flags & PF_KTHREAD))
		mmget(kit->data->mm);
	else
		kit->data->mm = NULL;
	spin_unlock(&task->alloc_lock);
	if (!kit->data->mm) {
		err = -ENOENT;
		goto err_cleanup_iter;
	}

	kit->data->snapshot.vm_file = NULL;
	kit->data->next_addr = addr;
	return 0;

err_cleanup_iter:
	put_task_struct(kit->data->task);
	bpf_mem_free(&bpf_global_ma, kit->data);
	/* NULL kit->data signals failed bpf_iter_task_vma initialization */
	kit->data = NULL;
	return err;
}

/*
 * Find and lock the next VMA at or after data->next_addr.
 *
 * lock_vma_under_rcu() is a point lookup (mas_walk): it finds the VMA
 * containing a given address but cannot iterate. An RCU-protected
 * maple tree walk with vma_next() (mas_find) is needed first to locate
 * the next VMA's vm_start across any gap.
 *
 * Between the RCU walk and the lock, the VMA may be removed, shrunk,
 * or write-locked. On failure, advance past it using vm_end from the
 * RCU walk. SLAB_TYPESAFE_BY_RCU can make vm_end stale, so fall back
 * to PAGE_SIZE advancement to guarantee forward progress.
 */
static struct vm_area_struct *
bpf_iter_task_vma_find_next(struct bpf_iter_task_vma_kern_data *data)
{
	struct vm_area_struct *vma;
	struct vma_iterator vmi;
	unsigned long start, end;

retry:
	rcu_read_lock();
	vma_iter_init(&vmi, data->mm, data->next_addr);
	vma = vma_next(&vmi);
	if (!vma) {
		rcu_read_unlock();
		return NULL;
	}
	start = vma->vm_start;
	end = vma->vm_end;
	rcu_read_unlock();

	vma = lock_vma_under_rcu(data->mm, start);
	if (!vma) {
		if (end <= data->next_addr)
			data->next_addr += PAGE_SIZE;
		else
			data->next_addr = end;
		goto retry;
	}

	if (unlikely(vma->vm_end <= data->next_addr)) {
		data->next_addr += PAGE_SIZE;
		vma_end_read(vma);
		goto retry;
	}

	return vma;
}

static void bpf_iter_task_vma_snapshot_reset(struct vm_area_struct *snap)
{
	if (snap->vm_file) {
		fput(snap->vm_file);
		snap->vm_file = NULL;
	}
}

__bpf_kfunc struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it)
{
	struct bpf_iter_task_vma_kern *kit = (void *)it;
	struct vm_area_struct *snap, *vma;

	if (!kit->data) /* bpf_iter_task_vma_new failed */
		return NULL;

	snap = &kit->data->snapshot;

	bpf_iter_task_vma_snapshot_reset(snap);

	vma = bpf_iter_task_vma_find_next(kit->data);
	if (!vma)
		return NULL;

	memcpy(snap, vma, sizeof(*snap));

	/*
	 * The verifier only trusts vm_mm and vm_file (see
	 * BTF_TYPE_SAFE_TRUSTED_OR_NULL in verifier.c). Take a reference
	 * on vm_file; vm_mm is already correct because lock_vma_under_rcu()
	 * verifies vma->vm_mm == mm. All other pointers are untrusted by
	 * the verifier and left as-is.
	 */
	if (snap->vm_file)
		get_file(snap->vm_file);

	kit->data->next_addr = vma->vm_end;
	vma_end_read(vma);
	return snap;
}

__bpf_kfunc void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it)
{
	struct bpf_iter_task_vma_kern *kit = (void *)it;

	if (kit->data) {
		bpf_iter_task_vma_snapshot_reset(&kit->data->snapshot);
		put_task_struct(kit->data->task);
		bpf_iter_mmput_async(kit->data->mm);
		bpf_mem_free(&bpf_global_ma, kit->data);
	}
}

__bpf_kfunc_end_defs();

#ifdef CONFIG_CGROUPS

struct bpf_iter_css_task {
	__u64 __opaque[1];
} __attribute__((aligned(8)));

struct bpf_iter_css_task_kern {
	struct css_task_iter *css_it;
} __attribute__((aligned(8)));

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_css_task_new(struct bpf_iter_css_task *it,
		struct cgroup_subsys_state *css, unsigned int flags)
{
	struct bpf_iter_css_task_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_css_task_kern) != sizeof(struct bpf_iter_css_task));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_css_task_kern) !=
					__alignof__(struct bpf_iter_css_task));
	kit->css_it = NULL;
	switch (flags) {
	case CSS_TASK_ITER_PROCS | CSS_TASK_ITER_THREADED:
	case CSS_TASK_ITER_PROCS:
	case 0:
		break;
	default:
		return -EINVAL;
	}

	kit->css_it = bpf_mem_alloc(&bpf_global_ma, sizeof(struct css_task_iter));
	if (!kit->css_it)
		return -ENOMEM;
	css_task_iter_start(css, flags, kit->css_it);
	return 0;
}

__bpf_kfunc struct task_struct *bpf_iter_css_task_next(struct bpf_iter_css_task *it)
{
	struct bpf_iter_css_task_kern *kit = (void *)it;

	if (!kit->css_it)
		return NULL;
	return css_task_iter_next(kit->css_it);
}

__bpf_kfunc void bpf_iter_css_task_destroy(struct bpf_iter_css_task *it)
{
	struct bpf_iter_css_task_kern *kit = (void *)it;

	if (!kit->css_it)
		return;
	css_task_iter_end(kit->css_it);
	bpf_mem_free(&bpf_global_ma, kit->css_it);
}

__bpf_kfunc_end_defs();

#endif /* CONFIG_CGROUPS */

struct bpf_iter_task {
	__u64 __opaque[3];
} __attribute__((aligned(8)));

struct bpf_iter_task_kern {
	struct task_struct *task;
	struct task_struct *pos;
	unsigned int flags;
} __attribute__((aligned(8)));

enum {
	/* all process in the system */
	BPF_TASK_ITER_ALL_PROCS,
	/* all threads in the system */
	BPF_TASK_ITER_ALL_THREADS,
	/* all threads of a specific process */
	BPF_TASK_ITER_PROC_THREADS
};

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_task_new(struct bpf_iter_task *it,
		struct task_struct *task__nullable, unsigned int flags)
{
	struct bpf_iter_task_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_task_kern) > sizeof(struct bpf_iter_task));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_task_kern) !=
					__alignof__(struct bpf_iter_task));

	kit->pos = NULL;

	switch (flags) {
	case BPF_TASK_ITER_ALL_THREADS:
	case BPF_TASK_ITER_ALL_PROCS:
		break;
	case BPF_TASK_ITER_PROC_THREADS:
		if (!task__nullable)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	if (flags == BPF_TASK_ITER_PROC_THREADS)
		kit->task = task__nullable;
	else
		kit->task = &init_task;
	kit->pos = kit->task;
	kit->flags = flags;
	return 0;
}

__bpf_kfunc struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it)
{
	struct bpf_iter_task_kern *kit = (void *)it;
	struct task_struct *pos;
	unsigned int flags;

	flags = kit->flags;
	pos = kit->pos;

	if (!pos)
		return pos;

	if (flags == BPF_TASK_ITER_ALL_PROCS)
		goto get_next_task;

	kit->pos = __next_thread(kit->pos);
	if (kit->pos || flags == BPF_TASK_ITER_PROC_THREADS)
		return pos;

get_next_task:
	kit->task = next_task(kit->task);
	if (kit->task == &init_task)
		kit->pos = NULL;
	else
		kit->pos = kit->task;

	return pos;
}

__bpf_kfunc void bpf_iter_task_destroy(struct bpf_iter_task *it)
{
}

__bpf_kfunc_end_defs();


/**
 * @brief
 *
 * @return int
 */
static int __init task_iter_init(void)
{
	int ret;

	task_reg_info.ctx_arg_info[0].btf_id = btf_task_file_ids[0];
	ret = bpf_iter_reg_target(&task_reg_info);
	if (ret)
		return ret;

	task_file_reg_info.ctx_arg_info[0].btf_id = btf_task_file_ids[0];
	task_file_reg_info.ctx_arg_info[1].btf_id = btf_task_file_ids[1];
	return bpf_iter_reg_target(&task_file_reg_info);
}
late_initcall(task_iter_init);