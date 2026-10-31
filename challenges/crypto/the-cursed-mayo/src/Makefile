CC ?= gcc
CMAKE ?= cmake
MAYO_DIR := MAYO-C
BUILD_DIR := ../build
MAYO_BUILD := $(BUILD_DIR)/mayo
MAYO_INC := -I$(MAYO_DIR)/include -I$(MAYO_DIR)/src -I$(MAYO_DIR)/src/common -I$(MAYO_DIR)/src/generic
MAYO_LIB := -L$(MAYO_BUILD)/src -lmayo -lmayo_common_sys
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -DENABLE_PARAMS_DYNAMIC -g0 -fno-ident
LDFLAGS ?= -static -Wl,--build-id=none
SIGNER := ../public/cursed_signer

all: $(SIGNER)

$(MAYO_BUILD)/src/libmayo.a:
	@mkdir -p $(MAYO_BUILD)
	$(CMAKE) -S $(MAYO_DIR) -B $(MAYO_BUILD) \
		-DMAYO_BUILD_TYPE=ref -DENABLE_AESNI=OFF -DENABLE_TESTS=OFF \
		-DMAYO_MARCH=-march=x86-64 >/dev/null
	$(CMAKE) --build $(MAYO_BUILD) -j$(shell nproc) >/dev/null

$(SIGNER): cursed_signer.c $(MAYO_BUILD)/src/libmayo.a
	@mkdir -p $(dir $(SIGNER))
	$(CC) $(CFLAGS) $(MAYO_INC) cursed_signer.c -o $(SIGNER) $(LDFLAGS) $(MAYO_LIB)
	strip --strip-debug $(SIGNER)
	chmod 755 $(SIGNER)

clean:
	rm -rf $(MAYO_BUILD) $(SIGNER)

.PHONY: all clean
