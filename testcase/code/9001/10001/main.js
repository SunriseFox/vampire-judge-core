let [a, b] = (await read()).split(' ').map(i => Number(i));
writeLine(a + b);