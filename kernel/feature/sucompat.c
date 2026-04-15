#include <linux/compiler_types.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "hook/syscall_hook.h"

#define KGSTSU_PATH "/dev/kgstsu"

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
    *value = ksu_su_compat_enabled ? 1 : 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_su_compat_enabled = enable;
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = "/system/bin/sh";

    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

#define kgstsu_sh_user_path() sh_user_path()

static char __user *ksud_user_path(void)
{
    static const char ksud_path[] = KSUD_PATH;

    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
    const char kgstsu[] = KGSTSU_PATH;
    uid_t uid = current_uid().val;

    /* 黑名单 UID 跳过路径替换 */
    if (is_blacklist_uid(uid)) {
        return 0;
    }

    /* 白名单模式: 非白名单 UID 跳过 */
    if (!is_whitelist_uid(uid)) {
        return 0;
    }

    char path[64];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!strncmp(path, kgstsu, sizeof(kgstsu) - 1) && path[sizeof(kgstsu) - 1] == '\0')) {
        pr_info("faccessat kgstsu->sh!\n");
        *filename_user = kgstsu_sh_user_path();
    }

    return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    const char kgstsu[] = KGSTSU_PATH;
    uid_t uid = current_uid().val;

    if (unlikely(!filename_user)) {
        return 0;
    }

    /* 黑名单 UID 跳过路径替换 */
    if (is_blacklist_uid(uid)) {
        return 0;
    }

    /* 白名单模式: 非白名单 UID 跳过 */
    if (!is_whitelist_uid(uid)) {
        return 0;
    }

    char path[64];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!strncmp(path, kgstsu, sizeof(kgstsu) - 1) && path[sizeof(kgstsu) - 1] == '\0')) {
        pr_info("newfstatat kgstsu->sh!\n");
        *filename_user = kgstsu_sh_user_path();
    }

    return 0;
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs)
{
    const char kgstsu[] = KGSTSU_PATH;
    const char __user *fn;
    char path[64];  /* 64 bytes to hold any path */
    long ret;
    unsigned long addr;
    uid_t uid = current_uid().val;

    if (unlikely(!filename_user))
        goto do_orig_execve;

    /* 黑名单 UID 跳过提权逻辑 */
    if (is_blacklist_uid(uid)) {
        pr_info("kgstsu: uid %d is blacklisted, skip\n", uid);
        goto do_orig_execve;
    }

    /* 白名单模式: 非白名单 UID 跳过提权 */
    if (!is_whitelist_uid(uid)) {
        goto do_orig_execve;
    }

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    memset(path, 0, sizeof(path));

    ret = strncpy_from_user(path, fn, sizeof(path));

    if (ret < 0) {
        pr_warn("Access filename when execve failed: %ld", ret);
        goto do_orig_execve;
    }

    /* 检测 kgstsu 命令 */
    if (!strncmp(path, kgstsu, sizeof(kgstsu) - 1) && path[sizeof(kgstsu) - 1] == '\0') {
        pr_info("kgstsu: found, escaping to root shell\n");
        /* sulog disabled for stealth */
        *filename_user = kgstsu_sh_user_path();

        ret = escape_with_root_profile();
        if (ret) {
            pr_err("kgstsu: escape_with_root_profile failed: %ld\n", ret);
            goto do_orig_execve;
        }

        ret = ksu_syscall_table[orig_nr](regs);
        if (ret < 0) {
            pr_err("kgstsu: failed to execve sh: %ld\n", ret);
        }
        return ret;
    }

do_orig_execve:
    return ksu_syscall_table[orig_nr](regs);
}

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void __exit ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
