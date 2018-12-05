/*
 * DECKARD LSM module
 *
 * based on root_plug.c
 * Copyright (C) 2002 Greg Kroah-Hartman <greg@kroah.com>
 *
 * _xx_is_valid(), _xx_encode(), _xx_realpath_from_path()
 * is ported from security/tomoyo/realpath.c in linux-2.6.32 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/moduleparam.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/fs_struct.h>
#include <linux/net.h>
#include <linux/netfilter_ipv4/ip_tables.h>

static int deckard_ptrace_may_access(struct task_struct *child, unsigned int mode)
{
	return -EPERM;
}

static int deckard_ptrace_traceme(struct task_struct *parent)
{
	return -EPERM;
}

static inline bool _xx_is_valid(const unsigned char c)
{
	return c > ' ' && c < 127;
}

static int _xx_encode(char *buffer, int buflen, const char *str)
{
	while (1) {
		const unsigned char c = *(unsigned char *) str++;

		if (_xx_is_valid(c)) {
			if (--buflen <= 0)
				break;
			*buffer++ = (char) c;
		if (c != '\\')
				continue;
			if (--buflen <= 0)
				break;
			*buffer++ = (char) c;
			continue;
		}
		if (!c) {
			if (--buflen <= 0)
				break;
			*buffer = '\0';
			return 0;
		}
		buflen -= 4;
		if (buflen <= 0)
			break;
		*buffer++ = '\\';
		*buffer++ = (c >> 6) + '0';
		*buffer++ = ((c >> 3) & 7) + '0';
		*buffer++ = (c & 7) + '0';
	}
	return -ENOMEM;
}

static int _xx_realpath_from_path(struct path *path, char *newname,
				  int newname_len)
{
	struct dentry *dentry = path->dentry;
	int error = -ENOMEM;
	char *sp;

	if (!dentry || !path->mnt || !newname || newname_len <= 2048)
		return -EINVAL;
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		sp = dentry->d_op->d_dname(dentry, newname + offset,
					   newname_len - offset);
	}
	else {
		/* Taken from d_namespace_path(). */
		struct path ns_root = { };
		struct path root;
		struct path tmp;

		read_lock(&current->fs->lock);
		root = current->fs->root;
		path_get(&root);
		read_unlock(&current->fs->lock);
		spin_lock(&vfsmount_lock);
		if (root.mnt && root.mnt->mnt_ns)
			ns_root.mnt = mntget(root.mnt->mnt_ns->root);
		if (ns_root.mnt)
			ns_root.dentry = dget(ns_root.mnt->mnt_root);
		spin_unlock(&vfsmount_lock);
		spin_lock(&dcache_lock);
		tmp = ns_root;
		sp = __d_path(path, &tmp, newname, newname_len);
		spin_unlock(&dcache_lock);
		path_put(&root);
		path_put(&ns_root);
	}
	if (IS_ERR(sp)) {
		error = PTR_ERR(sp);
	}
	else {
		error = _xx_encode(newname, sp - newname, sp);
	}
#if 1
	/* Append trailing '/' if dentry is a directory. */
	if (!error && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)
	    && *newname) {
		sp = newname + strlen(newname);
		if (*(sp - 1) != '/') {
			if (sp < newname + newname_len - 4) {
				*sp++ = '/';
				*sp = '\0';
			} else {
				error = -ENOMEM;
			}
		}
	}
#endif
	return error;
}

#ifndef CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH
#define CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH "/system/"
#endif
#ifndef CONFIG_SECURITY_DECKARD_SYSTEM_DEV_PATH
#define CONFIG_SECURITY_DECKARD_SYSTEM_DEV_PATH "/dev/block/mtdblock5"
#endif

#ifndef CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MAJOR
#define CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MAJOR (31)
#endif /* ! CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MAJOR */

#ifndef CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MINOR
#define CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MINOR (5)
#endif /* ! CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MINOR */

static int deckard_sb_mount(char *dev_name, struct path *path,
			    char *type, unsigned long flags, void *data)
{
	static char realpath[PATH_MAX];
	int r;
	struct block_device* bdev;
	unsigned char major, minor;

	r = _xx_realpath_from_path(path, realpath, PATH_MAX-1);
	if (r != 0) return r;

	if (strncmp(realpath, CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH,
		    strlen(CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH)) == 0) {
	  if (strcmp(realpath, CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH) == 0) {
	    if (strcmp(dev_name, CONFIG_SECURITY_DECKARD_SYSTEM_DEV_PATH) != 0) {
	      printk(KERN_ERR "%s: REJECT dev_name=%s realpath=%s\n",
		     __FUNCTION__, dev_name, realpath);
	      return -EPERM;
	    }
	    else {
	      if (flags & MS_BIND) {
	        printk(KERN_ERR "%s: REJECT dev_name=%s realpath=%s loopback mount\n",
	            __FUNCTION__, dev_name, realpath);

	        return -EPERM;
	      }

	      bdev = lookup_bdev((const char*)dev_name);

	      if( bdev == NULL ) {
	        printk("cannot lookup\n");

	        return -EPERM;
	      }

	      major = MAJOR(bdev->bd_dev);
	      minor = MINOR(bdev->bd_dev);

	      bdput(bdev);

	      if((major != CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MAJOR) || (minor != CONFIG_SECURITY_DECKARD_SYSTEM_DEV_MINOR)) {
	        printk(KERN_ERR "%s: REJECT dev_name=%s realpath=%s mismatch major or minor\n",
	            __FUNCTION__, dev_name, realpath);

	        return -EPERM;
	      }
	    }
	  }
	  else {
	    printk(KERN_ERR "%s: REJECT realpath=%s\n",
		   __FUNCTION__, realpath);
	    return -EPERM;
	  }
	}

	return 0;
}

#ifndef CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT
#define CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT "system"
#endif

static int deckard_sb_umount(struct vfsmount *mnt, int flags)
{
	(void)flags;

	if(mnt && mnt->mnt_mountpoint && 
	   strncmp(mnt->mnt_mountpoint->d_name.name, CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT,
	   strlen(CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT)) == 0) {
		printk(KERN_ERR "%s: REJECT mountpoint=%s\n", __FUNCTION__, mnt->mnt_mountpoint->d_name.name);

		return -EPERM;
	}

	return 0;
}

static int deckard_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	static char old_realpath[PATH_MAX];
	static char new_realpath[PATH_MAX];
	int r;

	r = _xx_realpath_from_path(old_path, old_realpath, PATH_MAX-1);
	if (r != 0) return r;

	r = _xx_realpath_from_path(new_path, new_realpath, PATH_MAX-1);
	if (r != 0) return r;

	printk(KERN_ERR "%s: REJECT old_path=%s new_path=%s\n",
	       __FUNCTION__, old_realpath, new_realpath);

	return -EPERM;
}

static int deckard_path_symlink(struct path *dir, struct dentry *dentry, const char *old_name)
{
	static char realdir[PATH_MAX];
	int r;

	r = _xx_realpath_from_path(dir, realdir, PATH_MAX - 1);

	if (r != 0) return r;

	if(strncmp(realdir, CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH,
		    strlen(CONFIG_SECURITY_DECKARD_SYSTEM_DIR_PATH)) == 0)
	{
		printk(KERN_ERR "%s: REJECT dir=%s\n", __FUNCTION__, realdir);

		return -EPERM;
	}

	if((strcmp(realdir, "/") == 0) && 
	    (strncmp(dentry->d_name.name, CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT, 
	            strlen(CONFIG_SECURITY_DECKARD_SYSTEM_MOUNT_POINT)) == 0))
	{
		printk(KERN_ERR "%s: REJECT dir + dentry=%s%s\n", __FUNCTION__, realdir, dentry->d_name.name);

		return -EPERM;
	}

	return 0;
}

static int deckard_path_link(struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry)
{
	return 0;
}

#if 0
#ifndef CONFIG_SECURITY_DECKARD_CHROOT_PATH
#define CONFIG_SECURITY_DECKARD_CHROOT_PATH ""
#endif
#endif

static int deckard_path_chroot(struct path *path)
{
	static char realpath[PATH_MAX];
	static char tmp[PATH_MAX];
	char *p, *p2;
	int r;

#ifdef CONFIG_SECURITY_DECKARD_CHROOT_PATH
	r = _xx_realpath_from_path(path, realpath, PATH_MAX-1);
	if (r != 0) return r;

	p = CONFIG_SECURITY_DECKARD_CHROOT_PATH;
	while (*p) {
		p2 = strchr(p, ':');
		if (p2) {
			strncpy(tmp, p, (p2 - p));
			tmp[p2 - p] = 0;
		}
		else {
			strcpy(tmp, p);
		}

		if (strcmp(tmp, realpath) == 0)
			return 0;

		if (p2) {
			p = p2 + 1;
		}
		else {
			p += strlen(p);
		}
	}

	return -EPERM;
#else
	return 0;
#endif
}

#define LOCAL_DECKARD_GUESS_PATH_MAX_LEN (128)

static char* deckard_guess_binary(struct task_struct* t, char* buf, int len)
{
	struct vm_area_struct* vm_area;
	struct file* file;
	char tmp[LOCAL_DECKARD_GUESS_PATH_MAX_LEN + 1];
	char* p = NULL;
	char* q = NULL;
	int i;

	read_lock(&tasklist_lock);

	if(t && t->mm && t->mm->mmap)
	{
		vm_area = t->mm->mmap;

		for(i = 0; i < t->mm->map_count; i++)
		{
			if(!vm_area)
			{
				break;
			}

			file = vm_area->vm_file;

			if(file)
			{
				memset(tmp, 0, LOCAL_DECKARD_GUESS_PATH_MAX_LEN + 1);

				p = d_path(&file->f_path, tmp, LOCAL_DECKARD_GUESS_PATH_MAX_LEN);

				if(p == NULL || (long)p == ENAMETOOLONG)
				{
					vm_area = vm_area->vm_next;

					continue;
				}

				if(p[0] == '/')
				{
					strncpy(buf, p, len);

					q = buf;

					break;
				}
			}

			vm_area = vm_area->vm_next;
		}
	}

	read_unlock(&tasklist_lock);

	return q;
}

#ifdef CONFIG_SECURITY_NETWORK

#define LOCAL_DECKARD_IPTABLE_PATH "/system/bin/iptables"
#define LOCAL_DECKARD_IPTABLE_PERMIT_PATH_0 "/system/bin/rild"
#define LOCAL_DECKARD_IPTABLE_PERMIT_PATH_1 "/system/bin/netd"

static int deckard_socket_setsockopt(struct socket *sock, int level, int optname)
{
	if(optname == IPT_SO_SET_REPLACE || optname == IPT_SO_SET_ADD_COUNTERS)
	{
		char buff[LOCAL_DECKARD_GUESS_PATH_MAX_LEN + 1];

		memset(buff, 0, LOCAL_DECKARD_GUESS_PATH_MAX_LEN + 1);

		if(deckard_guess_binary(current, buff, LOCAL_DECKARD_GUESS_PATH_MAX_LEN) == NULL)
		{
			return -EPERM;
		}

		if(strlen(buff) != strlen(LOCAL_DECKARD_IPTABLE_PATH))
		{
			return -EPERM;
		}

		if(strcmp(buff, LOCAL_DECKARD_IPTABLE_PATH) != 0)
		{
			return -EPERM;
		}

		if(current->parent == NULL)
		{
			return -EPERM;
		}

		memset(buff, 0, LOCAL_DECKARD_GUESS_PATH_MAX_LEN + 1);

		if(deckard_guess_binary(current->parent, buff, LOCAL_DECKARD_GUESS_PATH_MAX_LEN) == NULL)
		{
			return -EPERM;
		}

		if((strlen(buff) == strlen(LOCAL_DECKARD_IPTABLE_PERMIT_PATH_0)) && (strcmp(buff, LOCAL_DECKARD_IPTABLE_PERMIT_PATH_0) == 0))
		{
			return 0;
		}

		if((strlen(buff) == strlen(LOCAL_DECKARD_IPTABLE_PERMIT_PATH_1)) && (strcmp(buff, LOCAL_DECKARD_IPTABLE_PERMIT_PATH_1) == 0))
		{
			return 0;
		}

		return -EPERM;
	}
	else
	{
		return 0;
	}
}
#endif /* CONFIG_SECURITY_NETWORK */

static struct security_operations deckard_security_ops = {
	.ptrace_may_access =	deckard_ptrace_may_access,
	.ptrace_traceme =	deckard_ptrace_traceme,
	.sb_mount =		deckard_sb_mount,
	.sb_umount =		deckard_sb_umount,
	.sb_pivotroot =		deckard_sb_pivotroot,
#ifdef CONFIG_SECURITY_PATH
	.path_symlink =		deckard_path_symlink,
	.path_link =		deckard_path_link,
	.path_chroot =		deckard_path_chroot,
#endif
#ifdef CONFIG_SECURITY_NETWORK
	.socket_setsockopt =	deckard_socket_setsockopt,
#endif /* CONFIG_SECURITY_NETWORK */
};

static int __init deckard_init (void)
{
	if (register_security (&deckard_security_ops)) {
		printk (KERN_INFO "Failure registering DECKARD LSM\n");
			return -EINVAL;
	}

	printk (KERN_INFO "DECKARD LSM module initialized\n");

	return 0;
}

security_initcall (deckard_init);
