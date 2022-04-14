########################################################################
CC = cc

CFILE = sm3.c sm4.c bignum.c ecc.c sm2.c eccipccom.c func.c file.c

obj  = sm3.o  sm4.o bignum.o ecc.o sm2.o eccipccom.o func.o file.o

all:
	$(CC) -c $(CFILE)
	$(CC) -o client client.c $(obj) -lpthread
	$(CC) -o server server.c $(obj) -lpthread
	@mkdir build
	@mv $(obj) build
	@mv client server build

.PHONY : clean
clean:
	rm -r build

.PHONY : remake
remake:
	rm -r ./build
	make
