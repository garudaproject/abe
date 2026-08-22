LDFALGS = -ldflags="-s -w"

all: build

build:
	go build $(LDFALGS) -o ./bin/abe ./...

install:
	CGO_ENABLED=0 go install $(LDFALGS) ./...

release:
	goreleaser release --auto-snapshot --clean

unpack:
	./bin/abe unpack testdata/backup.ab
	./bin/abe unpack testdata/lock/backup.ab 12345678

pack:
	./bin/abe pack backup.tar

clean:
	rm -rf ./bin
