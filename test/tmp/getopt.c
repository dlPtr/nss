#include <unistd.h>
#include <stdio.h>


int main(int argc, char* argv[])
{
    char res;

    opterr = 1;

    while(-1 != (res = getopt(argc, argv, "a:b::c"))) {
        switch (res) {
            case 'a': {
                puts("a");
                printf("a arg is %s\n", optarg);
                break;
            }
            case 'b': {
                puts("b");
                printf("b arg is %s\n", optarg);
                break;
            }
            case 'c': {
                puts("c");
                printf("c arg is %s\n", optarg);
                break;
            }
            case '?': {
                puts("Bad para");
                break;
            }
        }
    }

    return 0;
}
