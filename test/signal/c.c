#include <stdio.h>

typedef void (*sighandler_t)(int);
sighandler_t signals(int signum, sighandler_t handler);

void foo()
{
    puts("helifoo");
}

int main()
{

    signals(1, foo());

    return 0;
}
