#include <stdio.h>
#include <signal.h>

void sighan()
{
    puts("Get SIGINT");
}

int main()
{
    signal(SIGINT, sighan);

    while(1);

    return 0;
}
