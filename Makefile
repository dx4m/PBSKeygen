SRCS 	= $(wildcard *.c)
OBJS	= $(SRCS:.c=.o)
OUTPUT	= PBSKeygen
CC	= gcc
LFLAGS	= -lssl -lcrypto
FLAGS	= 

all: $(OBJS)
	$(CC) -o $(OUTPUT) $(OBJS) $(LFLAGS)
	strip -s $(OUTPUT)
	rm -f $(OBJS)

$(OBJS): $(SRCS)
	$(CC) -c $(FLAGS) $(SRCS)

clean:
	rm -f $(OBJS) $(OUTPUT)
