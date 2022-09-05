linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags netgo
macos:
	GOOS=darwin GOARCH=amd64 go build
