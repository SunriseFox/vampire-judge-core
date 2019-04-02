set -ex;\
  g++ -pthread -O2 tracer.cpp -o tracer;
  g++ test_output.cpp -o output;
  g++ test_syscall.cpp -o syscall;
  g++ test_write.cpp -o write;
  time -p ./output > /tmp/test
  time -p ./tracer ./output > /dev/null
  time -p ./syscall > /tmp/test
  time -p ./tracer ./syscall > /dev/null
  time -p ./write > /tmp/test
  time -p ./tracer ./write > /dev/null