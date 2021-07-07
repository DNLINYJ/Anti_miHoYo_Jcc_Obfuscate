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
    CURL* curl; //����CURL���͵�ָ��
    CURLcode res;  //����CURLcode���͵ı��������淵��״̬��

    curl = curl_easy_init();  //��ʼ��һ��CURL���͵�ָ��,һ��curl_easy_init��ζ��һ���Ự�Ŀ�ʼ
    if (curl != NULL)
    {
        struct curl_slist* headers = NULL;

        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); //���301��302��ת����
        //����curlѡ��. ����CURLOPT_URL�����û�ָ��url. argv[1]�д�ŵ������д���������ַ
        curl_easy_setopt(curl, CURLOPT_URL, web_url.c_str());

        string strTmpStr;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, downloadCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strTmpStr);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);//����֤����

        res = curl_easy_perform(curl);

        //cout << strTmpStr.c_str();

        if (res != CURLE_OK) //����д��󣬴�ӡ��������Ϣ
            cout << curl_easy_strerror(res);

        curl_easy_cleanup(curl); //���������������һ���Ự.��curl_easy_init�������.
        return strTmpStr;
    }
}