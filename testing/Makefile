export RUST_TARGET_PATH:=${PWD}

.PHONY: test

run: test
	xargo xtest

test: ./src/test.s
	gcc -c ./src/test.s -o ./src/test.o
	gcc -c ./src/ap.s -o ./src/ap.o
	objcopy -O binary ./src/test.o ./src/test
	objcopy -O binary ./src/ap.o ./src/ap
	rm ./src/test.o ./src/ap.o

clean:
	xargo clean
	rm ./src/test ./src/ap
