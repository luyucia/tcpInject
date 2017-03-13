
#include "core.h"

void ConfigLoader::init(const char* configFile)
{
    // const char * ini_name = "../conf/conf.ini";
    // const char * s;
    ini = iniparser_load(configFile);
    // iniparser_dump(ini,stdout);
    // s = iniparser_getstring(ini,"test:host","127.0.0.1");
    // printf("host is :%s\n",s);
    // iniparser_freedict(ini);
}
const char* ConfigLoader::get(const char* field,const char* key,const char * defaultValue)
{
    char buff[128];
    sprintf(buff,"%s:%s",field,key);
    return iniparser_getstring(ini,buff,defaultValue);
}

void ConfigLoader::free()
{
    iniparser_freedict(ini);
}

int ConfigLoader::loadTemplate(string filepath,string key)
{
    char * buffer;
    // 使用文件流
    ifstream ifs;
    try{
        ifs.open(filepath.c_str(), ios::binary);

        // 测试文件中字符数目
        ifs.seekg(0, ios::end);
        long length = ifs.tellg();
        ifs.seekg(0, ios::beg);
        // 分配内存
        buffer = new char[length];
        // 读文件
        ifs.read(buffer, length);
        // 复制给FileString
        templateContent[key] = string(buffer);
        ifs.close();
        // 一定要释放内存
        delete[]buffer;
        // 读取文件
    }catch(exception& e){
        LOG_ERROR("%s open file [%s] failed.",e.what(),filepath.c_str());
        exit(1);
    }
}

const char* ConfigLoader::getTemplate(string key)
{
    // if (templateContent.count(key) > 0)
    // {
    //     return templateContent[key].c_str();
    // }else{
    //     printf("get null template\n");
    //     return "";
    // }
    // string a = templateContent[key];
    return templateContent[key].c_str();
}

void ConfigLoader::dump()
{
    iniparser_dump(ini,stdout);
}





