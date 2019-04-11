docker start judgecore
docker cp "judgecore/." judgecore:/usr/bin/judgecore
docker exec judgecore /bin/chmod +x ./compile.sh
docker exec judgecore ./compile.sh
docker commit judgecore  sunrisefox/judgecore:v1.0
