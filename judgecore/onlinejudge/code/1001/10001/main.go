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

	fmt.Println(1, 2)
	
	a, _ := reader.ReadString('\n')

	i, _ := strconv.Atoi(strings.TrimSpace(a))

	if (i == 3) {
		fmt.Println("RIGHT")
	} else {
		fmt.Println("WRONG")
	}
}
