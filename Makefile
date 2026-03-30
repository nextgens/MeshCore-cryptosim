CXX := g++
CXXFLAGS := -std=c++11 -O2 -Wall -Wno-comment
INCLUDES := -I lib/ascon -I lib/ed25519

APP_SRCS := simulator.cpp mesh-crypto.cpp fec.cpp prng.cpp
LIB_SRCS := \
	lib/ascon/hash.c \
	lib/ascon/permutations.c \
	lib/ascon/printstate.c \
	lib/ed25519/add_scalar.c \
	lib/ed25519/fe.c \
	lib/ed25519/ge.c \
	lib/ed25519/key_exchange.c \
	lib/ed25519/keypair.c \
	lib/ed25519/sc.c \
	lib/ed25519/seed.c \
	lib/ed25519/sha512.c \
	lib/ed25519/sign.c \
	lib/ed25519/verify.c

SRCS := $(APP_SRCS) $(LIB_SRCS)
TARGET := simulator

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRCS) -o $(TARGET) -lm

clean:
	rm -f $(TARGET)
