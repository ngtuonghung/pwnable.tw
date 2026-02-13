#include <stdio.h>

int main() {
    unsigned int x;
    int r = scanf("%u", &x);
    printf("r = %d\n", r);

    int c = getchar();
    printf("next char = '%c' (%d)\n", c, c);
}
