all: build

clean: 
	rm ./bin -rfv
	rm ./src/tss_data  -rfv

build: 
	rm ./bin -rfv
	mkdir bin
	go build -o ./bin/tssparty ./src/.

runsetup:
	./bin/tssparty setup

runsign:
	./bin/tssparty sign