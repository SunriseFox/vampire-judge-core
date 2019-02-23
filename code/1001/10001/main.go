package main

import (
  "bufio"
  "fmt"
  "os"
	"strconv"
	"strings"
)

func main() {

	reader := bufio.NewReader(os.Stdin)
	
	a, _ := reader.ReadString(' ')
	b, _ := reader.ReadString(' ')

	i, _ := strconv.Atoi(strings.TrimSpace(a))
	j, _ := strconv.Atoi(strings.TrimSpace(b))

	fmt.Println(i + j)
}