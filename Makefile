NAME ?= inbd
BUILD_DIR ?= output
INBM_VERSION ?= 5.0.0-dev

inbd:
	@# Help: builds INBM daemon binary
	@echo "---MAKEFILE INBM BUILD---"
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux \
	go build -trimpath -gcflags="all=-spectre=all -l" -asmflags="all=-spectre=all" \
	-o $(BUILD_DIR)/$(NAME) cmd/inbd/main.go
	@echo "---END MAKEFILE INBM BUILD---"
