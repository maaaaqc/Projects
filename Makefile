CC=gcc
LIBS=-lseccomp -lcap
CFLAGS=-g -Wall -Werror
SOURCE1=sr_container.c sr_container_helpers.c sr_container_utils.c
EXEC1=SNR_CONTAINER 

container: $(SOURCE1)
	$(CC) -o $(EXEC1) $(CFLAGS) $(SOURCE1) $(LIBS)

clean:
	rm $(EXEC1)
