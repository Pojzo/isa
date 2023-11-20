CC 		:= gcc
SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := ./

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

CPPFLAGS := -Iinclude -MMD -MP
CFLAGS   := -Wall -Wall -Wextra -pedantic -w -g
LDFLAGS  := 
LDLIBS   :=

CLIENT_SRC := $(SRC_DIR)/tftp_client.c $(SRC_DIR)/args_parser.c $(SRC_DIR)/utils.c $(SRC_DIR)/config.c
SERVER_SRC := $(SRC_DIR)/tftp_server.c $(SRC_DIR)/args_parser.c $(SRC_DIR)/utils.c $(SRC_DIR)/config.c

CLIENT_OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(CLIENT_SRC))
SERVER_OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SERVER_SRC))

all: $(BIN_DIR)/tftp_client $(BIN_DIR)/tftp_server

.PHONY: all clean

$(BIN_DIR)/tftp_client: $(CLIENT_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BIN_DIR)/tftp_server: $(SERVER_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/ $(OBJ_DIR)/:
	mkdir -p $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
