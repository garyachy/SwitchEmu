# source files.
SRC = main.cpp
 
OBJ = $(SRC:.cpp=.o)
 
OUT = ./dpdkpcap_test

#RTE_TARGET = x86_64-native-linuxapp-gcc
 
# include directories
INCLUDES = -I. -I$(RTE_SDK)/$(RTE_TARGET)/include

# include files
INCLUDE_FILES = -include $(RTE_SDK)/$(RTE_TARGET)/include/rte_config.h

# C++ compiler flags (-g -O2 -Wall)
CFLAGS = -g -D__STDC_LIMIT_MACROS
CFLAGS += -fPIC

CFLAGS += -DRTE_MACHINE_CPUFLAG_SSE \
                  -DRTE_MACHINE_CPUFLAG_SSE2 \
                  -DRTE_MACHINE_CPUFLAG_SSE3 \
                  -DRTE_MACHINE_CPUFLAG_SSSE3 \
                  -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3
 
# compiler
CC = g++
 
# library paths
LIBS += -Ldpdkpcap -ldpdkpcap
LIBS += -L$(RTE_SDK)/$(RTE_TARGET)/lib -lintel_dpdk
LIBS += -pthread
LIBS += -ldl
 
# compile flags
LDFLAGS = -g
LDFLAGS += -Wl,--no-as-needed

 
$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(INCLUDE_FILES) -c $^ -o $@

all: $(OUT)
 
clean:
	rm -f $(OBJ) $(OUT)
