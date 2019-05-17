.PHONY:captrue
captrue:
	g++ captrue/run_test.c -o captrue/run -lgtest -lpthread

.PHONY:filter
filter:
	g++ filter/run_test.c -o filter/run -lgtest -lpthread

.PHONY:analyze
analyze:
	g++ analyze/run_test.c -o analyze/run -lgtest -lpthread

.PHONY:clean
clean:
	rm -rf captrue/run analyze/run filter/run