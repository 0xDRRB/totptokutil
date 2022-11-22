TARGET  := totptokutil
WARN    := -Wall
DEBUG	:= -g
CFLAGS  := $(DEBUG) ${WARN} `pkg-config --cflags libnfc`
LDFLAGS := `pkg-config --libs libnfc` -lm
CC      := cc

C_SRCS    = $(wildcard *.c)
OBJ_FILES = $(C_SRCS:.c=.o)

all: ${TARGET}

%.o: %.c
	${CC} ${WARN} -c ${CFLAGS}  $< -o $@

${TARGET}: ${OBJ_FILES}
	${CC} ${WARN} -o $@  $(OBJ_FILES) ${LDFLAGS}

clean:
	rm -rf *.o ${TARGET}

leaktest: ${TARGET}
	valgrind --log-file=${TARGET}.leaklog --leak-check=yes --show-leak-kinds=definite ./${TARGET} -s INSWG2JAMVZXIIDVNZSSA5TSMFUW2ZLOOQ

mrproper: clean
	rm -rf *~
