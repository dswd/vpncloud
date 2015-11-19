default: libtapdev.a

tapdev.o: tapdev.c
	gcc -Os -c tapdev.c

libtapdev.a: tapdev.o
	ar rcs libtapdev.a tapdev.o


