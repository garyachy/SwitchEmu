main:		main.cpp
		c++ -g main.cpp classes.cpp -std=c++0x -o main tapcfg_bin-1.0.0/libtapcfg32.so -lpcap -lboost_thread -lboost_system

clean:		
		rm main
