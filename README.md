# 🙊 Tumbalong Phishing Detector

## Insanely accurate Phishing Detector

![Version - 1.0.0](https://img.shields.io/badge/Version-1.0.0-orange.svg)

## Authors

- 👍 박근표 - Machine Learning Designer
- 🍙 [이헌주 - Backend Developer](slave@c11.kr)

### Frameworks

|                           Framework                            | Description                                           |
| :------------------------------------------------------------: | :---------------------------------------------------- |
| [🌶 Flask](https://https://flask.palletsprojects.com/en/2.0.x/) | A Microframework based Python                         |
|            [Scikit-learn](https://scikit-learn.org)            | Simple & Efficient tools for predictive data analysis |

### Libraries and Packages

|                               Library                               | Description                                           |
| :-----------------------------------------------------------------: | :---------------------------------------------------- |
|                     [Numpy](https://numpy.org/)                     | A library for large, multi-dimensional array, metrics |
|                 [Pandas](https://pandas.pydata.org)                 | A library for data manipulation and analysis          |
|            [TLD](https://github.com/barseghyanartur/tld)            | A tool for extract TLD from URL                       |
| [BeautifulSoup4](http://www.crummy.com/software/BeautifulSoup/bs4/) | Easy to scrape tool for web                           |
|       [Python-whois](https://github.com/richardpenman/whois)        | Parse whois data                                      |

## Setup

### Prerequesites

- Python ^= 3.8
- Debian
- Mimimum 4GB RAM (Minimum AWS T~ Medium instance)

## Run with Docker

### Generate Docker Image from Dockerfile

1. `docker build -t tumbalong-phishing-detector .`

### Run

1. `docker run -itd -p 5000:5000 --name Tumbalong tumbalong-phishing-detector`

## Run without Docker

### pre-requirements

1. Install `Python 3.8`
2. Generate Folder and Execute Virtualenv `virtualenv venv`
3. Enter the isolated virtualenv $ `source venv/bin/activate`
4. Install Dependencies `pip install -r requirements.txt`

### Run ()

1. Enter the isolated virtualenv environment `source venv/bin/activate`
2. Execute `python main.py`
