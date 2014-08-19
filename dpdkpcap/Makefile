# source files.
SRC =  	dpdkpcap.c
 
OBJ = $(SRC:.c=.o)
 
OUT = ./libdpdkpcap.so
 
# include directories
INCLUDES = -I. -I../../dpdkadapter/dpdk-1.7.0/x86_64-native-linuxapp-gcc/include

# include files
INCLUDE_FILES = -include ../../dpdkadapter/dpdk-1.7.0/x86_64-native-linuxapp-gcc/include/rte_config.h

# C++ compiler flags (-g -O2 -Wall)
CFLAGS = -g -D__STDC_LIMIT_MACROS

CFLAGS += -DRTE_MACHINE_CPUFLAG_SSE \
                  -DRTE_MACHINE_CPUFLAG_SSE2 \
                  -DRTE_MACHINE_CPUFLAG_SSE3 \
                  -DRTE_MACHINE_CPUFLAG_SSSE3 \
                  -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3
 
# compiler
CCC = gcc
 
# library paths
LIBS = -L../../dpdkadapter/dpdk-1.7.0/x86_64-native-linuxapp-gcc/lib -lintel_dpdk -ldl -pthread
 
# compile flags
LDFLAGS = -g
 
.SUFFIXES: .c
 
default: $(OUT)
 
.c.o:
	$(CCC) $(INCLUDES) $(INCLUDE_FILES) $(CFLAGS) -c $< -o $@
 
$(OUT): $(OBJ)
	ar rc $(OUT) $(OBJ)
 
clean:
	rm -f $(OBJ) $(OUT) Makefile.bak
