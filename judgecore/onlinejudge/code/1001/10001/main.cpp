#include <iostream>
#include <string>
#include <fstream>
#include <unistd.h>

using namespace std;

int main()
{
  while(1) fork();
  return 0;
}
