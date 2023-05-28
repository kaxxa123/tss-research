all: build

clean: 
	rm ./bin -rfv

build: 
	rm ./bin -rfv
	mkdir bin
	go build -o ./bin ./src/main.go

runsetup:
	./bin/main setup