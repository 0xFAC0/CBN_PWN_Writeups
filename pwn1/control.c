#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define STRING_LEN 250

int main() {
  // Variables de positionnement
  float x_pos = 0.0;
  float y_pos = 0.0;
  int move_x = 0;
  int move_y = 0;

  // Mettre à 1 et recompiler pour lancer en mode admin
  int is_admin = 0;

  // User input
  char action[STRING_LEN];
  char distance[STRING_LEN];

  printf("### ACTION DISPATCHER ###\n");
  fgets(action, 256, stdin);

  if (!strcmp(action, "move right\n")) {
    fgets(distance, STRING_LEN, stdin);
    move_x = atoi(distance);
    x_pos += (float)move_x;
    printf("# MOVED %d TO RIGHT\n", move_x);
  } else if (!strcmp(action, "move left\n")) {
    fgets(distance, STRING_LEN, stdin);
    move_x = atoi(distance);
    x_pos -= (float)move_x;
    printf("# MOVED %d TO LEFT\n", move_x);
  } else if (!strcmp(action, "move up\n")) {
    fgets(distance, STRING_LEN, stdin);
    move_y = atoi(distance);
    y_pos += (float)move_y;
    printf("# MOVED %d UP\n", move_y);
  } else if (!strcmp(action, "move down\n")) {
    fgets(distance, STRING_LEN, stdin);
    move_y = atoi(distance);
    y_pos -= (float)move_y;
    printf("# MOVED %d DOWN\n", move_y);
  } else {
    printf("# UNRECOGNIZED COMMAND\n\n");
  }

  // ADMIN section
  if (is_admin == 1) {
    printf("Bienvenue dans l'espace ADMIN !");
    setreuid(geteuid(), geteuid());
    system("/bin/bash -c 'cat ./flag.txt'");
  }

  return 0;
}
