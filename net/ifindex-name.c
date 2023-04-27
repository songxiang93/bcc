
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [interface name]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    unsigned int if_index;
    if_index = if_nametoindex(argv[1]);
    if (if_index == 0) {
        fprintf(stderr, "Interface %s : No such device\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    printf("Interface %s : %d\n", argv[1], if_index);

    exit(EXIT_SUCCESS);
}