#include <string>
#include <curl/curl.h>
#include <iostream>
using namespace std;

static size_t downloadCallback(void* buffer, size_t sz, size_t nmemb, void* writer)
{
    string* psResponse = (string*)writer;
    size_t size = sz * nmemb;
    psResponse->append((char*)buffer, size);

    return sz * nmemb;
}

string get_web(string web_url)
{
    CURL* curl; //定义CURL类型的指针
    CURLcode res;  //定义CURLcode类型的变量，保存返回状态码

    curl = curl_easy_init();  //初始化一个CURL类型的指针,一般curl_easy_init意味着一个会话的开始
    if (curl != NULL)
    {
        struct curl_slist* headers = NULL;

        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); //解决301、302跳转问题
        //设置curl选项. 其中CURLOPT_URL是让用户指定url. argv[1]中存放的命令行传进来的网址
        curl_easy_setopt(curl, CURLOPT_URL, web_url.c_str());

        string strTmpStr;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, downloadCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strTmpStr);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);//忽略证书检查

        res = curl_easy_perform(curl);

        //cout << strTmpStr.c_str();

        if (res != CURLE_OK) //如果有错误，打印出错误信息
            cout << curl_easy_strerror(res);

        curl_easy_cleanup(curl); //这个调用用来结束一个会话.与curl_easy_init配合着用.
        return strTmpStr;
    }
}