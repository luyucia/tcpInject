#include <hiredis/hiredis.h>
#include <iostream>
#include <string.h>

using namespace std;

class Redis
{
public:
    static Redis * getInstance()
    {
        static Redis instance;
        return &instance;
    }
    char * execute(const char* cmd);
    void auth(const char* password);
    void select(int db);
    int connect(const char* host,int port,const char* password);
private:
    Redis(){}
    redisContext *pRedisContext;
    redisReply *pRedisReply;
    bool connected = false;
};
