#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((used, noinline, noreturn)) void win(void) {
    char flag[128];
    FILE *fp = fopen("flag.txt", "r");
    if (!fp || !fgets(flag, sizeof(flag), fp)) exit(1);
    puts(flag);
    fclose(fp);
    exit(0);
}

__attribute__((noinline)) void carve(void) {
    char pumpkin[64];
    puts("Carve your pumpkin:");
    /* Intentional stack overflow for this isolated CTF service. */
    read(STDIN_FILENO, pumpkin, 256);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    carve();
    return 0;
}
