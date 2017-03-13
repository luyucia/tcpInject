#include <unordered_set>
#include <unordered_map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

using namespace std;

class filterPolicy
{
public:
    filterPolicy(){};
    void loadPolicy(int push_total_times_p,int push_interval_p,string config_dir);
    bool canPush(const char * data,const struct ip* ip,const struct tcphdr * tcp,struct http_header* request,struct push_decide* push_decide);
    int loadFileToSet(string filepath,unordered_set<string> &set);
    int loadFileToSetIP(string filepath,unordered_set<long> &set);

    int getHttpHeader(const char *str, struct http_header *header,int http_content_offset);
    int parseHttpHeadOneLine(const char *data, struct http_header *header);

    ~filterPolicy(){};
private:
    // ip 名单
    unordered_set<long> ip_white_list;
    unordered_set<long> ip_black_list;
    // url 名单
    unordered_set<string> url_white_list;
    unordered_set<string> url_black_list;
    // 域名 名单
    unordered_set<string> host_white_list;
    unordered_set<string> host_black_list;

    unordered_set<string> js_black_list;

    unordered_map<string,long> push_cache;

    int push_total_times;
    int push_interval;
    regex_t reg_taobao;
    regex_t reg_etao;
    regex_t reg_ali_host;

    regex_t reg_360_browser;
    regex_t reg_360_weishi;
    regex_t reg_360_shadu;
    regex_t reg_360_browser2;

};
