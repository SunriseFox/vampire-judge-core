set -ex; \
  docker cp "testcase/." judgecore:/mnt/data; \
  docker exec judgecore bash -c "find /mnt/data -type d -exec chmod 755 {} \;"  \\
  docker exec judgecore ./judgecore /mnt/data/config/9001-a.json /mnt/data/config/9001-b.json /mnt/data/config/9001-c.json; \
  docker exec judgecore ./compiler /mnt/data/config/spj-9002.json; \
  docker exec judgecore ./judgecore /mnt/data/config/9002-a.json /mnt/data/config/9002-b.json /mnt/data/config/9002-c.json; \
  docker exec judgecore ./compiler /mnt/data/config/spj-9003.json; \
  docker exec judgecore ./judgecore /mnt/data/config/9003-a.json /mnt/data/config/9003-b.json /mnt/data/config/9003-c.json;
