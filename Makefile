TARGET=nss
CC=gcc

SRC=./src/*.c ./nss.c
CFLAG=-lpcap

INCLUDE_DIR=./include/
INCLUDE=./include/*.h
LIB_DIR=./lib/

$(TARGET):$(SRC) $(INCLUDE)
	$(CC) $(SRC) -o $(TARGET) -I $(INCLUDE_DIR) $(CFLAG)

.PHONY:install
install:
	cp nss /usr/bin
.PHONY:clean
clean:
	rm -f nss
