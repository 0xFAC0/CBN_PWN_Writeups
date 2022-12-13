#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CANARY_LEN 4
#define STRING_LEN 256

// ADMIN section
void admin_panel() {
    printf("Bienvenue dans l'espace ADMIN !");
    setreuid(geteuid(), geteuid());
    system("/bin/bash -c 'cat ./flag.txt'");
}

char secret[CANARY_LEN];
void set_secret() {
    FILE *canary_file = fopen("/secret.txt", "r");
    if (canary_file == NULL) {
        printf("ERREUR ! Impossible de lire le fichier canary\n");
        exit(0);
    }
    fread(secret, sizeof(char), CANARY_LEN, canary_file);
    fclose(canary_file);
}

void select_action(char *name) {
    // Stack smashing protection
    char canary[CANARY_LEN];

    // User input
    char action[STRING_LEN];

    memcpy(canary, secret, CANARY_LEN);

    printf("### ACTION DISPATCHER ###\nWelcome : ");
    printf(name);
    printf("\nACTION = ");
    scanf("%s", action);

    if(memcmp(canary, secret, CANARY_LEN)) {
        printf("ERREUR ! Tentative d'écrasement de la pile : petit canard maltraité !\n");
        exit(-1);
    }

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

int main(int argc, char *argv[]) {
    set_secret();
    select_action(argv[1]);
    return 0;
}

