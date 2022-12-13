all: exploit.c
	gcc exploit.c -m32 -o genexploit
	./genexploit
	hexdump ./evil
	cat ./evil | ./control
