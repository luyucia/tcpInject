#include "redis.h"

int Redis::connect(const char* host,int port,const char* password)
{
    struct timeval timeout = {2, 0};

    pRedisContext = (redisContext*)redisConnectWithTimeout(host, port, timeout);
    if ( (NULL == pRedisContext) || (pRedisContext->err) )
    {
        if (pRedisContext)
        {
            std::cout << "connect error:" << pRedisContext->errstr << std::endl;
        }
        else
        {
            std::cout << "connect error: can't allocate redis context." << std::endl;
        }
        return -1;
    }

    connected = true;
    auth(password);

    // redisCommand(pRedisContext, "auth MhxzKhl");
    //redisReply是Redis命令回复对象 redis返回的信息保存在redisReply对象中
    // redisReply *pRedisReply = (redisReply*)redisCommand(pRedisContext, "select 7");  //执行INFO命令
    // std::cout << pRedisReply->str << std::endl;
    //当多条Redis命令使用同一个redisReply对象时
    //每一次执行完Redis命令后需要清空redisReply 以免对下一次的Redis操作造成影响
    // freeReplyObject(pRedisReply);

}

void Redis::auth(const char* password)
{
    char cmd[64];
    sprintf(cmd,"auth %s",password);
    execute(cmd);
}

void Redis::select(int db)
{
    char cmd[64];
    sprintf(cmd,"select %d",db);
    execute(cmd);
}


char * Redis::execute(const char * cmd)
{
    if(connected){
        pRedisReply = (redisReply*)redisCommand(pRedisContext,cmd);

        if(pRedisReply!=NULL){
            return pRedisReply->str;
        }else{
            printf("redis command error-->%s \n",cmd);
            throw 1;
            return "";
        }
    }else{
        printf("cannot call execute() because redis not connected yet!\n");
        throw 1;
    }

}
