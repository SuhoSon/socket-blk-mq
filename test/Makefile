CC=gcc
TEST_OBJS=test.o
TEST_TEST=test

all: test

test: $(TEST_OBJS)
	$(CC) -o $(TEST_TEST) $^

clean:
	rm -rf $(TEST_OBJS) $(TEST_TEST)
