# source files.
SRC = main.cpp
 
OBJ = $(SRC:.cpp=.o)
 
OUT = ./dpdkpcap_test
 
# compiler
CC = g++

INCLUDES = -Idpdkpcap 

# library paths
LIBS += -Ldpdkpcap -ldpdkpcap
LIBS += -L$(RTE_SDK)/$(RTE_TARGET)/lib -lintel_dpdk
LIBS += -pthread
LIBS += -ldl
#LIBS += -lpcap
 
# compile flags
LDFLAGS = -g
LDFLAGS += -Wl,--no-as-needed

 
$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)
%.o: %.cpp
	$(CC) $(INCLUDES) -c $^ -o $@

all: $(OUT)
 
clean:
	rm -f $(OBJ) $(OUT)
