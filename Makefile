main:		main.cpp
		c++ -g main.cpp -o main -Ldpdkpcap -ldpdkpcap

clean:		
		rm main
