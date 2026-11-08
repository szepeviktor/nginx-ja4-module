NGINX_SOURCE ?= /usr/share/nginx/src
BUILD_DIR ?= $(CURDIR)/build

.PHONY: all test integration clean
all:
	mkdir -p "$(BUILD_DIR)"
	cp -a "$(NGINX_SOURCE)/." "$(BUILD_DIR)/"
	cd "$(BUILD_DIR)" && ./configure --with-compat --with-http_ssl_module --with-http_v2_module --add-dynamic-module="$(CURDIR)"
	$(MAKE) -C "$(BUILD_DIR)" -f objs/Makefile modules

test:
	python3 tests/test_ja4.py

integration:
	python3 tests/test_nginx.py

clean:
	rm -rf build tests/__pycache__
