export RUST_TARGET_PATH:=${PWD}

.PHONY: test

run: test
	xargo xtest

test: ./src/test.s
	gcc -c ./src/test.s -o ./src/test.o
	objcopy -O binary ./src/test.o ./src/test
	rm ./src/test.o

clean:
	xargo clean
	rm ./src/test
