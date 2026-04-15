#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dirent.h>

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

// 查找 kgking fd
int find_kgking_fd() {
    char path[256];
    char target[256];
    DIR *dir;
    struct dirent *ent;

    dir = opendir("/proc/self/fd");
    if (!dir) return -1;

    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;

        snprintf(path, sizeof(path), "/proc/self/fd/%s", ent->d_name);
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, "[kgking]") != nullptr) {
                closedir(dir);
                return atoi(ent->d_name);
            }
        }
    }
    closedir(dir);
    return -1;
}

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

int main() {
    printf("=== KernelSU 黑名单控制工具 ===\n");
    printf("注意: 此工具需要通过 /dev/kgstsu 提权后运行\n\n");

    int fd = find_kgking_fd();
    if (fd < 0) {
        printf("错误: 无法找到 [kgking] fd\n");
        printf("请确保以 root 权限运行此程序\n");
        return 1;
    }

    printf("找到 [kgking] fd=%d\n\n", fd);

    // 列出当前黑名单
    list_blacklist(fd);

    // 演示: 添加一个测试 UID
    printf("--- 添加测试 UID 12345 ---\n");
    add_blacklist(fd, 12345);

    // 再次列出
    list_blacklist(fd);

    // 演示: 移除测试 UID
    printf("--- 移除测试 UID 12345 ---\n");
    remove_blacklist(fd, 12345);

    // 最终列表
    list_blacklist(fd);

    return 0;
}
