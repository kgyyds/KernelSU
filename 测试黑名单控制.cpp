/*
 * KernelSU 白名单控制工具
 * 
 * 使用方式:
 *   echo UID > /dev/kgking
 * 
 * 示例:
 *   echo 10000 > /dev/kgking
 * 
 * 功能:
 *   1. 将指定 UID 添加到白名单
 *   2. 启用白名单模式
 *   3. 隐藏 /dev/kgking 设备
 * 
 * 注意: 执行后设备自动隐藏，需要重启才能重新使用
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("=== KernelSU 白名单工具 ===\n\n");
        printf("使用方法:\n");
        printf("  echo UID > /dev/kgking\n\n");
        printf("示例:\n");
        printf("  echo 10000 > /dev/kgking\n\n");
        printf("功能:\n");
        printf("  1. 将 UID 添加到白名单\n");
        printf("  2. 启用白名单模式\n");
        printf("  3. 隐藏 /dev/kgking 设备\n\n");
        printf("提示: 也可以直接使用 shell 命令:\n");
        printf("  echo 10000 > /dev/kgking\n");
        return 0;
    }

    int fd = open("/dev/kgking", O_WRONLY);
    if (fd < 0) {
        printf("错误: 无法打开 /dev/kgking\n");
        printf("请确保:\n");
        printf("  1. KernelSU 内核模块已加载\n");
        printf("  2. 以 root 权限运行\n");
        return 1;
    }

    // 写入 UID
    ssize_t written = write(fd, argv[1], strlen(argv[1]));
    if (written < 0) {
        perror("写入失败");
        close(fd);
        return 1;
    }

    printf("✅ UID %s 已添加到白名单\n", argv[1]);
    printf("✅ 白名单模式已启用\n");
    printf("✅ /dev/kgking 设备已隐藏\n");
    printf("\n需要重启才能重新使用此工具\n");

    close(fd);
    return 0;
}
