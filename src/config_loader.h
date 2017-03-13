#include <string>
#include <map>
#include "iniparser.h"
#include <fstream>
#include <unordered_set>

using namespace std;

class ConfigLoader
{
public:
    // ~ConfigLoader();
    const char* get(const char* field,const char* key,const char * defaultValue);
    void free();
    void init(const char* configFile);
    void dump();
    int loadTemplate(string filepath,string key);

    const char* getTemplate(string key);
    static ConfigLoader* getInstance()
    {
        static ConfigLoader instance;
        return &instance;
    }
private:
    ConfigLoader(){

    };
    dictionary * ini;
    string configFileName;
    // static ConfigLoader * m_instance;
    map<string, string>  templateContent;

};
