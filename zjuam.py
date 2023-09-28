import requests
from bs4 import BeautifulSoup
import logging

class ZJULogin:
    def __init__(self, url_login, headers):
        self.url_login = url_login
        self.headers = headers
        self.session = requests.Session()#实例化一个session，有利于保存cookies
        self.logger = self.setup_logger()  # 设置日志记录器

    def setup_logger(self):
        logger = logging.getLogger("ZJULogin")  # 创建一个名为 "ZJULogin" 的日志记录器
        logger.setLevel(logging.DEBUG)  # 设置记录器的日志级别为 DEBUG（最低级别）
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")  # 设置日志格式
        console_handler = logging.StreamHandler()  # 创建一个控制台处理程序，用于将日志信息输出到控制台
        console_handler.setLevel(logging.INFO)  # 设置控制台处理程序的日志级别为 INFO
        console_handler.setFormatter(formatter)  # 为控制台处理程序设置日志格式
        logger.addHandler(console_handler)  # 将控制台处理程序添加到日志记录器
        return logger  

    def get_key(self):#获得公钥
        try:
            url_get_key = 'https://zjuam.zju.edu.cn/cas/v2/getPubKey'#获取公钥的网站
            r1 = self.session.get(self.url_login, headers=self.headers, allow_redirects=True)
            r2 = self.session.get(url_get_key, headers=self.headers, allow_redirects=True)
            r2.raise_for_status()  # 检查响应是否成功
            j = r2.json()#公钥（模数和指数）在返回的json中
            modulus = j['modulus']#模数
            exponent = j['exponent']#指数
            return [self.transform_rsa(self.password, modulus, exponent), self.find_execution(r1)]#返回post所需要的所有数据

        except requests.exceptions.RequestException as e:
            self.logger.error(f"网络请求失败: {e}")
            return None

    def transform_rsa(self, m, N, e):#密码的RSA加密
        try:
            n = int.from_bytes(m.encode('ASCII'), byteorder='big')#将密码转化为ASCII码
            e = int(e, 16)
            N = int(N, 16)#变成16进制
            c = pow(n, e, N)#rsa加密的公式
            pwd = hex(c)[2:]#转化为16进制，但hex函数会在前两位生成0x，予以切除
            return pwd#返回加密后密码
        except Exception as e:
            self.logger.error(f"RSA加密失败: {e}")
            return None

    def find_execution(self, r):#寻找execution的值
        try:
            soup = BeautifulSoup(r.text, 'html.parser')
            execution = soup.find('input', attrs={"name": "execution"})['value']#寻找execution的值
            return execution
        except Exception as e:
            self.logger.error(f"查找 'execution' 值失败: {e}")
            return None

    def post(self, u, p, execution):#post登录过程
        try:
            data = {
                "username": u,
                "password": p,
                "execution": execution,
                "_eventId": "submit",
                "authcode": "",
            }
            r3 = self.session.post(self.url_login, headers=self.headers, data=data, allow_redirects=True)
            r3.raise_for_status()
            return r3
        except requests.exceptions.RequestException as e:
            self.logger.error(f"POST请求失败: {e}")
            return None

    def login(self, user_id, password):
        self.user_id = user_id
        self.password = password
        list1 = self.get_key()
        if list1:
            p = list1[0]#加密后密码
            execution = list1[1]#execution的值
            r3 = self.post(self.user_id, p, execution)
            if r3:
                return r3
            else:
                self.logger.error("登录失败")
                return None
        else:
            self.logger.error("登录失败")
            return None


url_login = 'https://zjuam.zju.edu.cn/cas/login'#登录网址
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36 Core/1.94.202.400 QQBrowser/11.9.5355.400'
}
user_id = input('请输入您的学号：')
password = input('请输入您的密码：')

zju_login = ZJULogin(url_login, headers)
response = zju_login.login(user_id, password)

if response and '统一身份认证' not in response.text:
    print('登录成功')
else:
    print('登录失败')