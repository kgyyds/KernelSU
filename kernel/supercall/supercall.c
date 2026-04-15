#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h" // for whitelist functions

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

// kgking misc device for blacklist management
bool kgking_hidden = false;
EXPORT_SYMBOL(kgking_hidden);

static long kgking_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    if (kgking_hidden) {
        return -ENODEV;
    }
    return anon_ksu_ioctl(filp, cmd, arg);
}

static const struct file_operations kgking_fops;

struct miscdevice kgking_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "kgking",
    .fops = &kgking_fops,
    .mode = 0666,
};
EXPORT_SYMBOL(kgking_miscdev);

// Hide kgking device
void do_hide_kgking(void)
{
    kgking_hidden = true;
    misc_deregister(&kgking_miscdev);
    pr_info("kgking: device hidden\n");
}

static ssize_t kgking_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[32];
    uid_t uid;

    if (kgking_hidden) {
        return -ENODEV;
    }

    if (count >= sizeof(kbuf)) {
        return -EINVAL;
    }

    if (copy_from_user(kbuf, buf, count)) {
        return -EFAULT;
    }
    kbuf[count] = '\0';

    // Parse UID
    if (kstrtouint(kbuf, 10, &uid) != 0) {
        pr_err("kgking: invalid UID format\n");
        return -EINVAL;
    }

    // Add to whitelist
    ksu_whitelist_add(uid);

    // Enable whitelist mode
    set_whitelist_mode(true);

    // Hide device immediately
    do_hide_kgking();

    pr_info("kgking: whitelist UID %u added, device hidden\n", uid);

    return count;
}

static const struct file_operations kgking_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = kgking_ioctl,
    .compat_ioctl = kgking_ioctl,
    .write = kgking_write,
    .release = anon_ksu_release,
};

int ksu_install_fd(void)
{
    struct file *filp;
    int fd;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        return fd;
    }

    filp = anon_inode_getfile("[kgking]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        close_fd(fd);
#else
        ksys_close(fd);
#endif
    }

    kfree(tw);
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);

    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
    }

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

    rc = register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }

    rc = misc_register(&kgking_miscdev);
    if (rc) {
        pr_err("kgking misc device register failed: %d\n", rc);
    } else {
        pr_info("kgking misc device registered: /dev/kgking\n");
    }
}

void __exit ksu_supercalls_exit(void)
{
    unregister_kprobe(&reboot_kp);
    ksu_supercall_cleanup_state();
}
