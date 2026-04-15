#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// ioctl 命令定义 (和内核一致)
struct BlacklistCmd {
    unsigned int uid;
};

struct BlacklistGetCmd {
    unsigned int count;
    unsigned int uids[64];
};

#define KSU_IOCTL_BLACKLIST_ADD    _IOW('K', 21, struct BlacklistCmd)
#define KSU_IOCTL_BLACKLIST_REMOVE _IOW('K', 22, struct BlacklistCmd)
#define KSU_IOCTL_BLACKLIST_GET    _IOWR('K', 23, struct BlacklistGetCmd)
#define KSU_IOCTL_HIDE_KGKING      _IO('K', 100)

#define KGKING_DEV "/dev/kgking"

// 列出黑名单
void list_blacklist(int fd) {
    BlacklistGetCmd cmd = {.count = 64};

    if (ioctl(fd, KSU_IOCTL_BLACKLIST_GET, &cmd) < 0) {
        perror("ioctl BLACKLIST_GET failed");
        return;
    }

    printf("\n=== 当前黑名单 (%u 个) ===\n", cmd.count);
    if (cmd.count == 0) {
        printf("  (空)\n");
    } else {
        for (unsigned int i = 0; i < cmd.count; i++) {
            printf("  UID: %u\n", cmd.uids[i]);
        }
    }
    printf("\n");
}

// 添加黑名单
void add_blacklist(int fd, unsigned int uid) {
    BlacklistCmd cmd = {.uid = uid};

    if (ioctl(fd, KSU_IOCTL_BLACKLIST_ADD, &cmd) < 0) {
        perror("ioctl BLACKLIST_ADD failed");
        return;
    }

    printf("已添加 UID %u 到黑名单\n", uid);
}

// 移除黑名单
void remove_blacklist(int fd, unsigned int uid) {
    BlacklistCmd cmd = {.uid = uid};

    if (ioctl(fd, KSU_IOCTL_BLACKLIST_REMOVE, &cmd) < 0) {
        perror("ioctl BLACKLIST_REMOVE failed");
        return;
    }

    printf("已从黑名单移除 UID %u\n", uid);
}

// 隐藏设备
void hide_kgking(int fd) {
    if (ioctl(fd, KSU_IOCTL_HIDE_KGKING) < 0) {
        perror("ioctl HIDE_KGKING failed");
        return;
    }

    printf("\n=== /dev/kgking 已隐藏 ===\n");
    printf("设备已删除，需要重启才能重新使用\n\n");
}

void print_usage(const char *prog) {
    printf("用法: %s <命令> [参数]\n\n", prog);
    printf("命令:\n");
    printf("  list                - 列出当前黑名单\n");
    printf("  add <uid>           - 添加 UID 到黑名单\n");
    printf("  remove <uid>         - 从黑名单移除 UID\n");
    printf("  hide                - 隐藏 /dev/kgking 设备 (永久)\n");
    printf("\n示例:\n");
    printf("  %s list\n", prog);
    printf("  %s add 10000\n", prog);
    printf("  %s remove 10000\n", prog);
    printf("  %s hide\n", prog);
}

int main(int argc, char *argv[]) {
    printf("=== KernelSU 黑名单控制工具 ===\n\n");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int fd = open(KGKING_DEV, O_RDWR);
    if (fd < 0) {
        printf("错误: 无法打开 %s\n", KGKING_DEV);
        printf("请确保 KernelSU 内核模块已加载\n");
        return 1;
    }

    printf("成功打开设备: %s (fd=%d)\n\n", KGKING_DEV, fd);

    if (strcmp(argv[1], "list") == 0) {
        list_blacklist(fd);
    } else if (strcmp(argv[1], "add") == 0 && argc == 3) {
        unsigned int uid = atoi(argv[2]);
        add_blacklist(fd, uid);
        list_blacklist(fd);
    } else if (strcmp(argv[1], "remove") == 0 && argc == 3) {
        unsigned int uid = atoi(argv[2]);
        remove_blacklist(fd, uid);
        list_blacklist(fd);
    } else if (strcmp(argv[1], "hide") == 0) {
        list_blacklist(fd);
        hide_kgking(fd);
    } else {
        print_usage(argv[0]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
