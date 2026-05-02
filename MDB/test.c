#include <stdio.h>

void foo() {
    static int i = 0;
    char *msg = "hello from foo";
    printf("%s %d\n", msg, i+1);
    i++;
}

int main() {
    foo();
    foo();
    foo();
    return 0;
}