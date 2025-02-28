# FUMVar
We used python 3.5 version.

## Installation
```
$ git clone https://github.com/FUMVar/FUMVar.git
```

## Requirements
* ssdeep
* lief
* numpy
* requests
* pandas
* pefile
* pyvirtualdisplay

## Virtual environment setting
```
$ virtualenv -p python3 venv
$ . ./venv/bin/activate
## ssdeep requirements
(venv) sudo apt-get install build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev
(venv) $ pip install -r requirements.txt
```

## Cuckoo sandbox execution
cuckoo.py has to be run on another window before running FUMVar.py.
```
(venv) $ python cuckoo.py
```

## How to run
Before you run the code you have to insert the VirusTotal api key to the `vt_api_key` file. You can add multiple VirusTotal api key in vt_api_key.
```
$ vim vt_api_key

#### insert your api key ####
```
after insert VirusTotal api key. This is an example, these keys are not valid.
```
$ vim vt_api_key

sdfsafasdfhghjkhsadfghsajdfgjhasghjfdgasjhfghasjdgfjhasgfhjasgfj
dfajshfkjsahfhjk1h32kj389yf8as9h12389dghfsa8fyh91huhfjksadhfjkhs
...
```
You can see the information by running FUMVar with --help option.
```
(venv) $ python FUMVar.py --help

usage: FUMVar.py [-h] -i INPUT_PATH -o OUTPUT_PATH [-p POPULATION]
                 [-m PERTURBATION] [-g GENERATION] [-s SKIP]

optional arguments:
  -h, --help       show this help message and exit
  -i INPUT_PATH    Path for binary input
  -o OUTPUT_PATH   Path for result
  -p POPULATION    Number of population (default=4)
  -m PERTURBATION  Number of perturbation per generation (default=4)
  -g GENERATION    Number of generation (default=100)
  -s SKIP          Number of skip time for VirusTotal scan generation
                   (default=5)

```

### Sample code for running and result
```
(venv) $ python FUMVar.py -i sample/sample.exe -o result/result.txt -p 2 -g 200 -m 1 -s 1
* Scanning original malware sample

Original file: sample/sample.exe
VirusTotal detection rate: 0.8235294117647058

* Starting GP malware generation

* 1 generation

* Member 0
Malware Functionality: True
VirusTotal detection rate: 0.7222222222222222
Applied perturbations: ['upx_pack']
Previously applied perturbations: []

* Member 1
Malware Functionality: True
VirusTotal detection rate: 0.7746478873239436
Applied perturbations: ['pert_dos_stub']
Previously applied perturbations: []

* 2 generation

* Member 0
Malware Functionality: True
VirusTotal detection rate: 0.7222222222222222
Applied perturbations: ['upx_pack']
Previously applied perturbations: []

* Member 1
Malware Functionality: True
VirusTotal detection rate: 0.7323943661971831
Applied perturbations: ['section_add']
Previously applied perturbations: [['upx_pack']]
```
