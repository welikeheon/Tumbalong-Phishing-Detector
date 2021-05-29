import whois
import ssl
import urllib.request
import socket
import numpy as np
import re
import urllib.parse
import concurrent.futures
from tld import get_tld
from urllib.request import urlopen
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def check_IP_Address(url):
    parse = urllib.parse.urlparse(url, allow_fragments=False)
    domain = parse.netloc.split('.')
    domain_length = len(domain)

    if domain_length == 4:
        for i in range(0, domain_length-1):
            try:
                int(domain[i], 0)
                return -1
            except ValueError:
                return 1
    else:
        return 1


def check_URL_Length(url):
    url_length = len(url)

    if url_length < 54:
        return 1
    elif url_length >= 54 and url_length <= 75:
        return 0
    else:
        return -1


def check_AT_Symbol(url):
    if '@' in url:
        return -1
    else:
        return 1


def check_Hyphen(url):
    parse = urllib.parse.urlparse(url, allow_fragments=False)
    domain = parse.netloc

    if '-' in domain:
        return -1
    else:
        return 1


def remove_www(url):
    if "www." in url[:12]:
        url = url.replace("www.", "")
    return url


def check_Sub_Domain(url):
    url = remove_www(url)
    parse = urllib.parse.urlparse(url, allow_fragments=False)
    domain = parse.netloc
    dot_count = domain.count('.')

    if dot_count < 3:
        return 1
    elif dot_count == 3:
        return 0
    else:
        return -1


# SSL 인증서 검증


# https socket 연결
def https_connect(url):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=url)
    try:
        s.connect((url, 443))
    except Exception as e:
        return -1

    return s

# trusted issuer file 읽기


def get_trusted_issuer():
    f = open("trusted_issuer.txt", "r")

    trusted_issuer = []
    for line in f:
        issuers = line.strip('\n')
        trusted_issuer.append(issuers)
    return trusted_issuer


def check_SSL(url):
    try:
        # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
        parse = urllib.parse.urlparse(url, allow_fragments=False)
        domain = parse.netloc
        s = https_connect(domain)
        cert = s.getpeercert()
    except Exception as e:       # 타임아웃 에러 https를 사용하지 않는 것으로 판단 의심으로 분류
        return -1
    # cert = s.getpeercert()
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['organizationName']

    trusted_issuer_list = get_trusted_issuer()

    for CA_Owner in trusted_issuer_list:     # 신뢰 CA_Owner 중 검사 url CA_Owner가 포함되어있는지 검사
        if issued_by in CA_Owner:
            return 1
    else:
        return -1

    nonAfter = cert['nonAfter']    # 유효기간 검출 코드
    notBefore = cert['notBefore']
    init_date = parse(notBefore)
    expiration_date = parse(notBefor)
    if total_days >= 365:
        return 1
    else:
        return -1

# 도메인 등록기간


# 유효기간 계산


def get_total_date(url):
    domain = whois.whois(url)

    if type(domain.expiration_date) is list:
        expiration_date = domain.expiration_date[0]
    else:
        expiration_date = domain.expiration_date

    if type(domain.updated_date) is list:
        updated_date = domain.updated_date[0]
    else:
        updated_date = domain.updated_date

    if expiration_date == None:
        return -1
    elif updated_date == None:
        return -1
    else:
        total_date = (expiration_date - updated_date).days

    return total_date


def check_Domain_registration_period(url):
    try:
        total_date = get_total_date(url)
        if total_date <= 365:
            return -1
        else:
            return 1
    except whois.parser.PywhoisError:
        return -1


# '//'가    https:// 뒤에 존재하면 피싱사이트


def check_double_slash(url):
    parse = urllib.parse.urlparse(url)
    path = parse.path
    if '//' in path:
        return -1
    else:
        return 1

# 이 특징의 구현은 완전하지 않기때문에 넣을지 말지 생각해 보아야한다.


# 보통 사이트에서는 favicon을 자신의 웹서버 안에 갖고있는 경우가 많지만 피싱사이트의 경우 다른 곳에서 가져오는 경우가 있어 다른 사이트에서 favicon을 가져올 경우 피싱사이트로 분류


def check_Favicon(url):
    resp = urlopen(url, timeout=10)
    soup = BeautifulSoup(resp, 'html.parser')
    parse_url = urlparse(url)
    tld = get_tld(url, as_object=True)

    tag_link = soup.findAll("link", rel=re.compile("^shortcut icon$", re.I))

    if not tag_link:
        tag_link = soup.findAll("link", rel=re.compile("^icon$", re.I))
    if not tag_link:
        return 0

    for link in tag_link:
        fav = link.get('href')
        parse_fav = urlparse(fav)

        if parse_fav.hostname == "":
            return 1
        elif tld.domain in fav:
            return 1

    return -1


# 비표준 포트 사용 검사

# HTTPS 검사, domain으로 받기

def check_port_scan(url):
    # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
    parse = urllib.parse.urlparse(url, allow_fragments=False)
    domain = parse.netloc
    try:
        ip = socket.gethostbyname(domain)
    except:
        return -1

    socket.setdefaulttimeout(2)

    # 80번 포트만 열려있다면? ==> 1
    # 80번 포트 이외에 다른 포트가 공공에 열려있다면..? ==> -1

    ports_status = {}

    # for port in ports:
    def check_status(port):
        s = socket.socket()
        try:
            s.connect((ip, port))
            s.close()
            ports_status[port] = True
        except:
            ports_status[port] = False

    with concurrent.futures.ThreadPoolExecutor() as executor:
        ports = [80, 21, 22, 23, 445, 1433, 1521, 3306, 3389]
        executor.map(check_status, ports)

    if ports_status[80] == True:
        ports_status.pop(80)
        for _ in ports_status.values():
            if _ == True:
                return -1
    else:
        return -1

    return 1


# request url 얼마나 다른 곳에서 이미지, 비디오를 가져다 쓰느냐 페이지 소스중 video, img 외부 비율 검사
# request url 얼마나 다른 곳에서 이미지, 비디오를 가져다 쓰느냐 페이지 소스중 video, img 외부 비율 검사               좀더 수정필요 피싱사이트, 안전사이트 샘플 몇개 함수에 넣어보고 피싱, 정상 분류 비율 보고 수정하기


def vid_percent(web_url):
    with urllib.request.urlopen(web_url) as response:
        html = response.read()
        soup = BeautifulSoup(html, 'html.parser')
    all_vid = soup.find_all("video")

    # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
    parse = urllib.parse.urlparse(web_url, allow_fragments=False)
    domain = parse.netloc
    same = 0

    url_list = []
    for url_ap in all_img:
        url_list.append(str(url_ap))

    for check in url_list:
        if domain in check:
            same += 1

    if len(all_vid) == 0:
        return 0
    else:
        extern = len(all_vid) - same
        percent = extern / len(all_vid)

    return percent


def check_request_url(url):
    try:
        total_percent = vid_percent(url) + img_percent(url)
        if total_percent < 0.22:
            return 1
        elif total_percent < 0.61:
            return 0
        else:
            return -1
    except Exception as e:       # 오류발생시 없거나 https를 사용하지 않는등 피싱사이트의 특징이기 때문에 피싱사이트로 분류
        return -1


def check_web_traffic(url, alexalist):
    # alexadata = np.genfromtxt("majestic_million.csv",
    #                           delimiter=',', dtype="|U")
    # alexalist = alexadata[0:1000000, 2]

    # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
    parse = urllib.parse.urlparse(url, allow_fragments=False)
    domain = parse.netloc

    if domain in alexalist:
        return 1
    else:
        return -1


def img_percent(web_url):
    with urllib.request.urlopen(web_url) as response:
        html = response.read()
        soup = BeautifulSoup(html, 'html.parser')
    all_img = soup.find_all("img")
    img_list = []
    for i in range(len(all_img)):
        img_src = soup.find("img")
        img_url = img_src.get("src")

        # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
        img_parse = urllib.parse.urlparse(img_url, allow_fragments=False)
        img_domain = img_parse.netloc

        img_list.append(str(img_domain))

    # URL을 https:// 이런 형식으로 입력하지 않을시 netloc을 찾지 못하는 오류 발생
    parse = urllib.parse.urlparse(web_url, allow_fragments=False)
    domain = parse.netloc
    same = 0
    for check in img_list:
        if domain in check:
            same += 1
    if len(all_vid) or same == 0:
        return 0
    else:
        percent = same / len(all_img)

    return percent
