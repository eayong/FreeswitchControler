TARGET = controler

openssl 	= 1
debug 		= 1
use_event	= epoll

OUT_DIR = ./bin
 
$(shell if [ ! -d $(OUT_DIR) ]; then mkdir $(OUT_DIR) -p;fi;)


CFLAGS = -c -Wall -D__STDC_FORMAT_MACROS

INCLUDE_DIR = -I./include -I./thirdparty/esl -I./thirdparty/iniparser
LIB_DIR = ./libs

OBJECTS += ./src/main.o
OBJECTS += ./src/controler.o
OBJECTS += ./src/ctrl_conf.o
OBJECTS += ./src/ctrl_log.o
OBJECTS += ./src/ctrl_process.o
OBJECTS += ./src/sock_base.o
OBJECTS += ./src/sock_client.o
OBJECTS += ./src/sock_server.o
OBJECTS += ./src/sock_tcp.o
OBJECTS += ./src/units.o
OBJECTS += ./src/ctrl_connect.o
OBJECTS += ./src/ctrl_event.o
OBJECTS += ./thirdparty/iniparser/dictionary.o
OBJECTS += ./thirdparty/iniparser/iniparser.o

LIB_OPENSSL =
ifeq ($(openssl), 1)
	OBJECTS += ./src/sock_ssl.o
	OBJECTS += ./src/ssl_context.o
	LIB_OPENSSL = -lssl -lcrypto
	CFLAGS += -DHAS_OPENSSL
endif

ifeq ($(use_event), epoll)
	OBJECTS += ./src/epoll_event.o
	CFLAGS += -DHAS_EPOLL_EVENT
else
	ifeq ($(use_event), select)
	endif
endif

ifeq ($(debug), 1)
	COMPFLAG = -g -rdynamic
else
 	COMPFLAG = -O2
endif



COMPILER = gcc
LINKER   = gcc

$(TARGET) : $(OBJECTS)
	$(LINKER) $(OBJECTS) $(COMPFLAG) -o $(OUT_DIR)/$(TARGET) $(LIB_OPENSSL) $(LIB_DIR)/libesl.a -lpthread



.SUFFIXES:
.SUFFIXES: .c .o .cpp

.cpp.o:
	$(COMPILER) -o $*.o $(COMPFLAG) $(CFLAGS)  $(INCLUDE_DIR) $*.cpp

.c.o:
	$(COMPILER) -o $*.o $(COMPFLAG) $(CFLAGS)  $(INCLUDE_DIR) $*.c
	

all: $(TARGET)

clean:
	rm -f $(OBJECTS)
	rm -rf $(OUT_DIR)/*
	

