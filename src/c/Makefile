default: libtuntap.a

tapdev.o: tuntap.c
	gcc -Os -c tuntap.c

libtapdev.a: tuntap.o
	ar rcs libtuntap.a tuntap.o
