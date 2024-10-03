test: main.o src/utils.o src/safe_alloc.o src/readpe.o src/read_element.o
	gcc -o $@ $^

%.o: %.c
	gcc -c -o $@ $^ -g -Wall -Wextra -fanalyzer -I./

clean:
	rm src/*.o
	rm main.o