#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#include <random>
#include <algorithm> // generate_n

#include <unistd.h> // fork, execl

#include <sys/types.h> // waitpid, kill
#include <sys/wait.h>

using namespace std;

int create_folder(const string& path);
int remove_folder(const string& path);
int copy_file(const string& from, const string& dest);
string readFile(const string& filename);
string readFile(const string& filename, std::string::size_type count);
string random_string(size_t length);

#endif // UTILS_H