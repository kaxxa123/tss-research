all: build

clean: 
	rm ./bin -rfv
	rm ./src/tss_data  -rfv

build: 
	rm ./bin -rfv
	mkdir bin
	go build -o ./bin/main ./src/.

runsetup:
	./bin/main setup

runsign:
	./bin/main sign