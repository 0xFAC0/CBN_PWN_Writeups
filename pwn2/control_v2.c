#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STRING_LEN 256

void select_action() {
    // User input
    char action[STRING_LEN];

    printf("### ACTION DISPATCHER ###\n");
    scanf("%s", action);

    if (!strcmp(action, "right")) {
        printf("# MOVED RIGHT\n");
    }
    else if (!strcmp(action, "left")) {
        printf("# MOVED LEFT\n");
    }
    else if (!strcmp(action, "up")) {
        printf("# MOVED UP\n");
    }
    else if (!strcmp(action, "down")) {
        printf("# MOVED DOWN\n");
    }
    else {
        printf("# UNRECOGNIZED COMMAND\n\n");
    }
}

// ADMIN section
void admin_panel() {
    printf("Bienvenue dans l'espace ADMIN !");
    setreuid(geteuid(), geteuid());
    system("/bin/bash -c 'cat ./flag.txt'");
}

int main() {
    select_action();
    return 0;
}
