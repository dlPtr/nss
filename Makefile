TARGET=nss
CC=gcc

SRC=./src/*.c ./nss.c
CFLAG=-lpcap

INCLUDE_DIR=./include/
INCLUDE=./include/*.h
LIB_DIR=./lib/

$(TARGET):$(SRC) $(INCLUDE)
	$(CC) $(SRC) -o $(TARGET) -I $(INCLUDE_DIR) $(CFLAG)

.PHONY:gtest
gtest: 
	 g++ nss_gtest.cc src/*.c -o nss_gtest -lgtest -lpthread -lpcap -I ./include/ -fpermissive -w

.PHONY:install
install:
	cp nss /usr/bin

.PHONY:clean
clean:
	rm -f nss nss_gtest
