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

class KgkingTool {
private:
    int fd;

    void print_menu() {
        printf("\n");
        printf("╔══════════════════════════════════════╗\n");
        printf("║       KernelSU 黑名单控制工具        ║\n");
        printf("╠══════════════════════════════════════╣\n");
        printf("║  1. 列出黑名单                        ║\n");
        printf("║  2. 添加 UID 到黑名单                 ║\n");
        printf("║  3. 从黑名单移除 UID                  ║\n");
        printf("║  4. 查找 UID 是否在黑名单中           ║\n");
        printf("║  5. 隐藏设备 (永久删除 /dev/kgking)   ║\n");
        printf("║  0. 退出                             ║\n");
        printf("╚══════════════════════════════════════╝\n");
        printf("\n请选择操作: ");
    }

    void list_blacklist() {
        BlacklistGetCmd cmd = {.count = 64};

        if (ioctl(fd, KSU_IOCTL_BLACKLIST_GET, &cmd) < 0) {
            perror("  [错误] ioctl BLACKLIST_GET 失败");
            return;
        }

        printf("\n┌─────────────────────────────┐\n");
        printf("│      当前黑名单 (%u 个)      │\n", cmd.count);
        printf("├─────────────────────────────┤\n");

        if (cmd.count == 0) {
            printf("│         (空)                │\n");
        } else {
            for (unsigned int i = 0; i < cmd.count; i++) {
                printf("│  UID: %-10u              │\n", cmd.uids[i]);
            }
        }
        printf("└─────────────────────────────┘\n");
    }

    void add_blacklist() {
        printf("请输入要添加的 UID: ");
        unsigned int uid;
        if (scanf("%u", &uid) != 1) {
            printf("  [错误] 无效的输入\n");
            return;
        }

        BlacklistCmd cmd = {.uid = uid};
        if (ioctl(fd, KSU_IOCTL_BLACKLIST_ADD, &cmd) < 0) {
            perror("  [错误] ioctl BLACKLIST_ADD 失败");
            return;
        }

        printf("  [成功] UID %u 已添加到黑名单\n", uid);
    }

    void remove_blacklist() {
        printf("请输入要移除的 UID: ");
        unsigned int uid;
        if (scanf("%u", &uid) != 1) {
            printf("  [错误] 无效的输入\n");
            return;
        }

        BlacklistCmd cmd = {.uid = uid};
        if (ioctl(fd, KSU_IOCTL_BLACKLIST_REMOVE, &cmd) < 0) {
            perror("  [错误] ioctl BLACKLIST_REMOVE 失败");
            return;
        }

        printf("  [成功] UID %u 已从黑名单移除\n", uid);
    }

    void find_blacklist() {
        printf("请输入要查找的 UID: ");
        unsigned int uid;
        if (scanf("%u", &uid) != 1) {
            printf("  [错误] 无效的输入\n");
            return;
        }

        BlacklistGetCmd cmd = {.count = 64};
        if (ioctl(fd, KSU_IOCTL_BLACKLIST_GET, &cmd) < 0) {
            perror("  [错误] ioctl BLACKLIST_GET 失败");
            return;
        }

        bool found = false;
        for (unsigned int i = 0; i < cmd.count; i++) {
            if (cmd.uids[i] == uid) {
                found = true;
                break;
            }
        }

        if (found) {
            printf("  [结果] UID %u 在黑名单中\n", uid);
        } else {
            printf("  [结果] UID %u 不在黑名单中\n", uid);
        }
    }

    bool hide_device() {
        printf("\n⚠️  警告: 隐藏设备后将永久删除 /dev/kgking\n");
        printf("    需要重启手机才能重新使用此工具\n");
        printf("\n确认隐藏? (输入 'yes' 确认): ");

        char confirm[16];
        if (scanf("%s", confirm) != 1) {
            return false;
        }

        if (strcmp(confirm, "yes") != 0) {
            printf("  [取消] 操作已取消\n");
            return false;
        }

        if (ioctl(fd, KSU_IOCTL_HIDE_KGKING) < 0) {
            perror("  [错误] ioctl HIDE_KGKING 失败");
            return false;
        }

        printf("\n✅ /dev/kgking 已隐藏，设备已永久删除\n");
        return true;
    }

public:
    bool init() {
        fd = open(KGKING_DEV, O_RDWR);
        if (fd < 0) {
            printf("❌ 无法打开 %s\n", KGKING_DEV);
            printf("请确保:\n");
            printf("  1. KernelSU 内核模块已加载\n");
            printf("  2. 以 root 权限运行\n");
            return false;
        }
        printf("✅ 已连接到 %s (fd=%d)\n", KGKING_DEV, fd);
        return true;
    }

    void run() {
        while (true) {
            print_menu();

            int choice;
            if (scanf("%d", &choice) != 1) {
                printf("  [错误] 无效的输入\n");
                while (getchar() != '\n');  // 清空输入缓冲区
                continue;
            }

            switch (choice) {
                case 1:
                    list_blacklist();
                    break;
                case 2:
                    add_blacklist();
                    break;
                case 3:
                    remove_blacklist();
                    break;
                case 4:
                    find_blacklist();
                    break;
                case 5:
                    if (hide_device()) {
                        close(fd);
                        return;
                    }
                    break;
                case 0:
                    printf("再见!\n");
                    close(fd);
                    return;
                default:
                    printf("  [错误] 无效的选项\n");
                    break;
            }
        }
    }
};

int main() {
    printf("╔══════════════════════════════════════╗\n");
    printf("║    KernelSU 黑名单控制工具 v1.0       ║\n");
    printf("╚══════════════════════════════════════╝\n");

    KgkingTool tool;
    if (!tool.init()) {
        return 1;
    }

    tool.run();
    return 0;
}
