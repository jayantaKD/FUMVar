import pickle
import sys
import os
import time
from argparse import ArgumentParser

import lief

import gp
import analysis as anal

import logging
from malconv_nn import malconv
import shutil
import vt
import perturbation as p
import subprocess


def AKMVG():
    skip = 20
    perturbation = 1
    peDirectory = '/home/infobeyond/workspace/VirusShare/AKMVG/malwares'
    elfDirectory = '/home/infobeyond/workspace/VirusShare/AKMVG/elfMalwares'
    peOutputPath = '/home/infobeyond/workspace/VirusShare/AKMVG/peoutput'
    elfOutputPath = '/home/infobeyond/workspace/VirusShare/AKMVG/elfoutput'

    output_path = elfOutputPath #'/home/infobeyond/workspace/VirusShare/AKMVG/output1'
    input_directory = elfDirectory #'/home/infobeyond/workspace/VirusShare/AKMVG/malwares'

    # input_directory = '/home/vboxuser/database/AKMVG/malwares/'
    # output_path = '/home/vboxuser/database/AKMVG/output1'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_20130711'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_High_DR'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_Low_DR'
    #generationList = [50, 100, 150, 200, 250, 300]
    #populationList = [10, 50, 100]

    generationList = [50]
    populationList = [2, 5, 10, 15, 20]


    # with open(output_path, "a") as wf:
    #     wf.write("Original_File_Name" + ";"
    #              + "Variant_File_Name" + ";"
    #              + "Scanner" + ";"
    #              + "Total_Gen" + ";"
    #              + "Total_Population" + ";"
    #              + "Generation_No." + ";"
    #              + "Population_No." + ";"
    #              + "Delay" + ";"
    #              + "Functional" + ";"
    #              + "Ssdeep Score" + ";"
    #              + "VT Score" + ";"
    #              + "Fitness Score" + ";"
    #              + "Perturbation" + " \n")

    # peFiles = [
    #     # 'VirusShare_ae6af24501520d8e9e069cf6e85fb87a',
    #     #      'VirusShare_16a6955696ef375f1efb1d371cd9928c',
    #     #      'VirusShare_c78120aa5124274b458ebbdce5cd60ce',
    #     #      'VirusShare_4625556d1816142a1f8250bed15a834e',
    #     #      'VirusShare_01db10a317194fe7c94a58fae14f787c',
    #     #      'VirusShare_c0785f417aaf685af51c1212a0aa955c',
    #     #      'VirusShare_a7a3dbf9dd16606262d647c7d5814be1',
    #     #      'VirusShare_f5a3a06c99e01b856e55b3a178cedd51',
    #     #      'VirusShare_e0f6ef60c2d34dd49042ed5b287ce087',
    #     #      'VirusShare_7926a3a1708da681d54dd1a6ea45be37',
    #     #      'VirusShare_7970c24a511a6e6ae6b7c21a2deb371e',
    #     #      'VirusShare_2c75605732e53ab5eda618bcc2a1042d',
    #     #      'VirusShare_8452649012c7f2546c71f71518a06812',
    #     #      'VirusShare_29748f96daca16266b9ded60531f916e',
    #     #      'VirusShare_cdcc63adaa351be416b61da0dffb2c2c',
    #     #      'VirusShare_9715bbe0c4f594da9bbd99d2887f2061',
    #     #      'VirusShare_fdbde2e1fb4d183cee684e7b9819bc13',
    #     #      'VirusShare_487abbadd74e843ddaa0da3af36769e5',
    #     #      'VirusShare_37435ddc3ff4a1b3d76139bf2ff2a76e',
    #     #      'VirusShare_cadb6eccee60be126c2725b561833c75',
    #     #      'VirusShare_55da827a2e1e53de9a99a5a7be8e6e80',
    #     #      'VirusShare_09d49c997fa5df14cbefd9b745e04acf',
    #     #      'VirusShare_e2c82a0891c23d5afc86cfd6115e6b7c',
    #     #      'VirusShare_d3367aef91417ee4991ed7680c0ca5df',
    #     #      'VirusShare_73555509028ef8d62f50b1a57ad3c809',
    #          'VirusShare_1e34b50b8af8dbeb750c291981428053'
    # ]

    # fileList = '/home/infobeyond/workspace/VirusShare/peMalwaresList'
    fileList = '/home/infobeyond/workspace/VirusShare/elfMalwaresList'
    fileStartNo = 1
    fileEndNo = 10
    files = []
    with open(fileList) as f:
        counter = 1
        for filename in f:
            if fileStartNo <= counter <= fileEndNo:
                files.append(filename.strip())

    # Multiple malware in the directory
    for filename in files:
        # Varying number of total generations
        input_path = os.path.join(input_directory, filename)

        if not os.path.isfile(input_path):
            continue

        for generation in generationList:
            # Varying number of initial population list
            for population in populationList:
                savedFileName = gp.pickleSaveDirectory + str(filename) + '_' + str(generation) + '_' + str(population)
                isSaved = os.path.isfile(savedFileName)

                if isSaved:
                    with open(savedFileName, 'rb') as savedFile:
                        # Step 3
                        g = pickle.load(savedFile)
                        original = g.original
                else:
                    # print("* Scanning original malware sample")
                    fbytes = open(input_path, "rb").read()
                    original = gp.origin(input_path, fbytes, generation, filename, 'malonv')
                    print("\nOriginal Malware File: " + filename)
                    print("Malconv detection rate (%): " + str(round(original.vt_result*100, 2)))

                    print("\nStarting AKMVG Algorithm (Total Gen: "+str(generation)+", Populations per Gen: "
                          + str(population) + ")\n")
                    # print("* 1 generation\n")
                    g = gp.GP(fbytes, population, perturbation, output_path, skip, original)

                g.execute()
                print('-----------------------------------------------------------------------------------------------')
                print('-----------------------------------------------------------------------------------------------')
    pass

def PEmalwareCollection():
    inputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/MalwareBazar_batch_02_PE/'
    # inputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/'
    outputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/'
    n_network = malconv('./malconv/malconv.h5')
    files = os.listdir(inputDirectory)
    i = 0
    for f in files:
        i = i + 1
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %)")
        binary = inputDirectory + f
        prediction = n_network.predict(binary)

        if prediction > .98:
            print(str(binary) + '---->' + str(prediction))
            shutil.copy(inputDirectory + f.strip(), outputDirectory + f.strip())
            os.remove(inputDirectory + f.strip())

        # if f.endswith('incremental_original'):
        #     print(str(f))
        #     os.remove(binary)
    pass

def ELFmalwareCollection():
    inputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/VirusShare_ELF_20200405/'
    outputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/'

    files = os.listdir(inputDirectory)
    i = 0

    analysisIds = []
    scannedFileNames = []
    scannedFilePaths = []
    keyCount = 0
    exceptionCount=1
    vt_client = vt.Client(anal.apikeylist[keyCount])
    for f in files:
        i = i + 1
        binary = inputDirectory + f

        with open(binary, "rb") as f_scan:
            while True:
                try:
                    analysis = vt_client.scan_file(f_scan)
                    print(analysis.id)
                    analysisIds.append(analysis.id)
                    scannedFileNames.append(f)
                    scannedFilePaths.append(binary)
                    break

                except:
                    print('exception')

                    if exceptionCount > len(anal.apikeylist):
                        time.sleep(300)
                        exceptionCount = 1

                    vt_client.close()
                    keyCount = (keyCount + 1) % len(anal.apikeylist)
                    vt_client = vt.Client(anal.apikeylist[keyCount])
                    exceptionCount = exceptionCount + 1

        if i > 1000:
            break

    vt_client.close()
    print(analysisIds)
    print(scannedFileNames)
    print(scannedFilePaths)

    i = 0
    vt_client = vt.Client(anal.apikeylist[0])
    for analysisId in analysisIds:
        while True:
            vt_report = vt_client.get_object("/analyses/{}", analysisId)

            if vt_report.status == "completed":
                vt_result = vt_report.stats["malicious"] / (
                            vt_report.stats['undetected'] + vt_report.stats["malicious"])
                if vt_result > .60:
                    print(str(scannedFilePaths[i]) + '---->' + str(vt_result))
                    shutil.copy(scannedFilePaths[i], outputDirectory + scannedFileNames[i].strip())
                os.remove(scannedFilePaths[i])
                i = i + 1
                break
            else:
                print(str(scannedFilePaths[i]) + '---->' + str(vt_report.status))
            time.sleep(30)

    vt_client.close()
    pass

def list_malware_names(sourceDirectory='/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/',
                       outputFile='/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwaresList'):
    files = os.listdir(sourceDirectory)
    with open(outputFile, "a") as wf:
        i = 0
        for f in files:
            i = i + 1
            print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %)")
            wf.write(str(f.strip()) + "\n")
            pass

def checkElfFormat():
    # sourceDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/'
    sourceDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/VirusShare_ELF_20200405/'

    files = os.listdir(sourceDirectory)

    i=0
    for f in files:
        i = i + 1
        isELF = lief.is_elf(sourceDirectory + f.strip())

        if isELF:
            fbytes = open(str(sourceDirectory) + f, "rb").read()
            liefParsed = lief.parse(fbytes)

            try:
                if str(liefParsed.header.file_type) != 'E_TYPE.EXECUTABLE':
                    print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
                    # print('ELF Type: ' + str(liefParsed.header.file_type))
                    # print('Section Header Table Address: 0x' + str(liefParsed.header.section_header_offset))
                    # print('Section Header Table Size: ' + str(liefParsed.header.section_header_size) + ' bytes')
                    # print('Program Header Table Address: 0x' + str(liefParsed.header.program_header_offset))
                    # print('Program Header Table Size: ' + str(liefParsed.header.program_header_size) + ' bytes')

                    print(
                        '-------------------------------------------------------------------------------------------------------')
            except:
                pass
        else:
            print('Not a ELF file!!!!!')

    pass

def transferOverSCP():
    sourceDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/'
    scpDest = "infobeyond@192.168.1.93:~/workspace/VirusShare/peMalwares/"
    # dest = '/media/infobeyond/Jay/peMalwares/'

    files = os.listdir(sourceDirectory)

    i = 1
    for f in files:
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
        # shutil.copy(sourceDirectory+f.strip(), dest+f.strip())
        p = subprocess.Popen(["sshpass", "-p", "Inf0Bey0nd!",
                              "scp", sourceDirectory + f.strip(), scpDest + f.strip()])
        os.waitpid(p.pid, 0)
        i = i + 1

if __name__ == "__main__":
    # logging.getLogger().disabled = True
    # PEmalwareCollection()
    # list_malware_names()
    # ELFmalwareCollection()

    # analysisIds = ['ODZmNmM0Zjk3YzUyODQ1ODU3NjhhMmUyMWY5YjI0YTA6MTY4MDY0MDI2MQ==', 'ODZmOTk0NGUxYWIzYzY5ZDhkYTM0ZmVkZDY3ZDY4OWM6MTY4MDY0MDI2Mg==', 'ODZmOWJlZTUyMzE5ZGY1YTc1NTgyMmJhZjkwNGQwMzg6MTY4MDY0MDI2NA==', 'ODZmYWNiMGRmZDRjYzUzMWFjZGZlNzNiMGNmODA3OWM6MTY4MDY0MDI2Ng==', 'ODZmZGM4MjM3ZWRjNDNlMDUyMTA4ZmExODk2YmU5ZGU6MTY4MDY0MDI2Nw==', 'ODZmZmE2YTFjNTc1M2I4YjJmMzkxZmU1ODJkN2EwYzY6MTY4MDY0MDI2OQ==', 'YzM3MzNmYmUyZTY2MmQ0YzhiMDZiODUzNzcwMDhjYmE6MTY4MDY0MDI3MA==', 'YzM3NTlhOWE5YzU2Nzg2ZTA5MmZkYzlmOTU0NTEyMjQ6MTY4MDY0MDI3Mg==', 'YzM3NWZkM2UyZDJmYThjYzFlNDM0NGMyNGU0Yjk1MTc6MTY4MDY0MDI3Mw==', 'YzM3YzBlYTFiZjFmNDJmNmY2NmZiZDkwN2NjNDFmM2E6MTY4MDY0MDI3NQ==', 'YzM3YzU5MjI0OGQ5YjczMGJmYWQzYjEwZmI1MzhjOTQ6MTY4MDY0MDI3Ng==', 'YzM3ZTQzNGQwNjM4YjQ4NzZiMjY2NWFkMGE1NzA4ZDA6MTY4MDY0MDI3Nw==', 'YzM3ZjkzMmU5YTI5OWU5OTA0Yzc4NTNlOGVkOWFlNGI6MTY4MDY0MDI3OQ==', 'NjRiYjlkMzczODgxZDc4MTIyZGQxOGM0ODVjNjhlMTg6MTY4MDY0MDI4MA==', 'NjRjMDljODdlZWY0NWY0N2JhMThmMDNkODMxNDZhMjQ6MTY4MDY0MDI4Mg==', 'NjRjMTEzZjE5YjE0NTQ5ODkwZWM3MTRkNWEwYjM3YjE6MTY4MDY0MDI4NA==', 'NjRjMzA0N2FhOTQ0NjFlZWU3N2ZhODk0YzQxZWJlZjM6MTY4MDY0MDI4Ng==', 'NjRjNTRiY2VmZjlkOGIyMjVlZGI3YzU4NjUzMTYwNDM6MTY4MDY0MDI4OA==', 'NjRjNmYwNDlhMTQ2ZTE1ZjEzOTQ0ODZlZmQ5Y2I2MDQ6MTY4MDY0MDI4OQ==', 'NjRjYzMxMTljY2FmNTY4MzdiNWM5ZGMzYzZjYmY0NTQ6MTY4MDY0MDI5MA==', 'NjRkMDM5M2YwOGUxYWExNGQyMzUzNjgxN2M0Njk4NDk6MTY4MDY0MDI5Mg==', 'NjRkM2E1ZjFmMjA5Mzg2ZGI1MGUwNWFmN2RmNDI5YTM6MTY4MDY0MDI5NA==', 'NjRkOGMyNTg5MjhlMzgyMDcyZGZhMDQ5YzI4MjFjYjM6MTY4MDY0MDI5NQ==', 'NjRkOTE2OTllNTJkNzYwZGIwODc2OWUyMjAyN2M1ZjE6MTY4MDY0MDI5Nw==', 'NjRkYTU5MGFkMzdhY2E2ZDBkNDE2ZDBlMGNiNzg5Yjc6MTY4MDY0MDI5OA==', 'NjRkYjgwMmRiYzQ1ODdkOTczOGQyOWI1NjVhNTJkNmQ6MTY4MDY0MDMwMA==', 'NjRkZDZmZWFlYjhhYzM2ZDFjYTdiN2EyZDQzMTZkMmE6MTY4MDY0MDMwMg==', 'NjRkZGE4OWQ5ZjI5NTRjNGI2NTBmYzdhZGE3MjU4M2U6MTY4MDY0MDMwMw==', 'MDAxOTE3NzZjNzA2YzZjMjI3ZmQ4YTMxZjljODc3M2Q6MTY4MDY0MDMwNQ==', 'MDAzZjZkNDU0YzY3NzcxZjAwNDRjYWU2M2Y0ZmY0Yjg6MTY4MDY0MDMwNg==', 'MDA1Mzk0NzQwMTNkN2ExZDJkODYyZGY4NjBjZjg1ZjM6MTY4MDY0MDMwOA==', 'MDA3NWZiM2Q2Yzk1Nzc4YjVlZWJmOTcyNWNiYTQzY2U6MTY4MDY0MDMwOQ==', 'MDBhZjc1MjU3YTU0YWU4NzcyYTc3ODk3YWFhOGUyZDQ6MTY4MDY0MDMxMQ==', 'MDBkZTk5ZGNiNTliN2ViNGYwZTNjNjMxNjNiZjVkMmI6MTY4MDY0MDMxMg==', 'MDEwNzE0MmYwZGUyM2YwYzNhN2M4OTY4OGU4YTE4MjA6MTY4MDY0MDMxNA==', 'MDEzMzIxYjQ0ODVmZWVmZDlmY2RiMGM3MjQyYTdlYWY6MTY4MDY0MDMxNQ==', 'MDE0NTk3NjQxODcxNmI0MzM3NjMzN2Q1NDhiNzUwY2Y6MTY4MDY0MDMxNw==', 'MDE1ZmMzMjdjZWUwOTQxMGQ4ODA2MjczOTJjOGNmZmU6MTY4MDY0MDMxOA==', 'MDE3ZjEwYjZkMmZkY2I4OGY0NjYzN2RmMDIxOThlNTQ6MTY4MDY0MDMxOQ==', 'MDFhMWZmNDQ5NTQ2YWY3OThmNGZkM2UxZWIzZTRmYmE6MTY4MDY0MDMyMA==', 'MDFjNmZjMjVmODA4ZGM3NDJhODg0ZmExZTEzZjgxNDE6MTY4MDY0MDMyMg==', 'MDFkZmYzODM3YTQwZWU1OTY2ODNkMDdkZmMyMzc5OTQ6MTY4MDY0MDMyMw==', 'MDFmY2UwNjIyNWIxZTEyZTg2Mzc0OTcyM2YxMTVlZWM6MTY4MDY0MDMyNQ==', 'MDIxODZkYmU1YzVjNzc1OGVmODkzMDY2ZWY5YTViZmY6MTY4MDY0MDMyNw==', 'MDI0MDBkMWY4NmQxODJmNWFmMDE4ZDA2ZTgwNTM1NmI6MTY4MDY0MDMyOA==', 'MDI3NDM4ZWZkZGQwOWZiMDU1OTRlOTZlMjE2N2NjYTI6MTY4MDY0MDMzMA==', 'MDI4NGFjNzA5MzFiMjczMzRlMDcxOWFhNzA3MGQ1NGY6MTY4MDY0MDMzMQ==', 'ZWE1NTg3NTc1MGJiNjI5ZmRiY2Y0OTliOWFjZWQ2NTY6MTY4MDY0MDMzMw==', 'ZWE1N2NjMjVlOGQwNzE4ZmRjOWIyODdlZTZlNTZjMTc6MTY4MDY0MDMzNA==', 'ZWE1YTVmMjI5MGNlYjE0NmZkYmQwNGRiNTdlOTI0Yzk6MTY4MDY0MDMzNg==', 'ZWE1YzMxOTk2ZjBlMDk4NGY4YmZmMGM1MjVjOGQwMmE6MTY4MDY0MDMzNw==', 'ZWE2NTAwYjc1OWFiNDZmYjVlOGZjNmViYWMwM2E2MDU6MTY4MDY0MDMzOQ==', 'ZWE2Nzc0MDAwZjMxMjU4MzQ4NWM3NjA2NzQ1YjFlOWI6MTY4MDY0MDM0MA==', 'ZWE2OTFmZjQxNTFmNDdkYjZiODRkMTE2OWE0MjliY2I6MTY4MDY0MDM0Mg==', 'ZWE2ZDI2OTU2NmQzNDU1NjU4NjJjMzQ5OWViNWM3NWY6MTY4MDY0MDM0Mw==', 'ZWE2ZmQyNjM5ZThjZjliNDcxYTE1NmQ5ODkxNWRjOTc6MTY4MDY0MDM0NQ==', 'ZWE3MDFjNGY0OWE3MGEyYTJmMzNjNjE5ZDQxNzJhZmQ6MTY4MDY0MDM0Ng==', 'M2QzOWQ3YWJkYjkyZWI0OTIxN2NlNmVjY2ZlN2E5MDM6MTY4MDY0MDM0OA==', 'M2Q0MTI2ZjdiMmQxMzI5MjYxZDYwN2NjMGI2M2MyNWQ6MTY4MDY0MDM0OQ==', 'M2Q0MWVmYjdkNTk5MGU2YTg5ZGY0YjQ5MzRjNzc1N2E6MTY4MDY0MDM1MA==', 'M2Q0NDU5YWVmOTc1ZjI4NTcyZTk3MTUxMDM5NDQyMzg6MTY4MDY0MDM1Mg==', 'M2Q0NTgyMmRlZDU3YWQwMDRhM2IwOGNkZDJlOTZiYWQ6MTY4MDY0MDM1Mw==', 'M2Q0ODYyYzI3MTQ5M2E4YWQ5NGRjZjg0M2FhNjRjZDI6MTY4MDY0MDM1NQ==', 'M2Q0ODgxODNiNjlhMzFkZDc4M2JhMDJkZjg4MGE0MDY6MTY4MDY0MDM1Ng==', 'M2Q0YjE5MTFkOTUwODhkNzc1ZDMzNTU2NzFjYTFmNmQ6MTY4MDY0MDM1OA==', 'M2Q0YzU3M2RkN2IzMTVjZWJiN2I2MjBhN2IwZjdiYjM6MTY4MDY0MDM1OQ==', 'M2Q0ZWY0ZTk5YmNkNjQ1MDk4MzM1MTA3NjZmZDA0MjM6MTY4MDY0MDM2MQ==', 'YWQ4ZjNkOTQ4YmI0N2VhZDhhMGI3NDY0NDRlMmU1ZTY6MTY4MDY0MDM2Mw==', 'YWQ5MzViMWQwNTFiYmFlMWM0ZGQyNDhjMjk4YTU2YTU6MTY4MDY0MDM2NA==', 'YWQ5NGY3ZDcxZjYyNzQyMTIyYzkyNDM2MDhjYTEyMmY6MTY4MDY0MDM2Ng==', 'YWQ5OWI2NGQyYWFlNDU1M2I2YjY4NzcwMzNmOGVhMzQ6MTY4MDY0MDM2Nw==', 'YWQ5YzljOWY4OGYxNjM1ZTJlZDA2MjkwZWNjOWE3YTg6MTY4MDY0MDM2OA==', 'YWQ5ZDRhZDZlMjI4YTk1Y2I0ZTlmNGMwNmUyYmQ5OWU6MTY4MDY0MDM3MA==', 'YWQ5ZDczODYxMGU4ZDY1NzBkZGQ2NDQwNGQ3YTg5OWM6MTY4MDY0MDM3MQ==', 'YWRhMGZiMDc2N2ExNGJmNWNjZGRkYmIyNTQ1NTQ0NGM6MTY4MDY0MDM3Mw==', 'YWRhNGFlYmNlNzc0MWQxMjIwNmQwYzAwZTFjY2JkYjE6MTY4MDYzOTQ3NA==', 'YWRhNWQzODdlMjY1Y2QyODU0MDI5ZTQwYThiNzM3ZWE6MTY4MDYzOTQ3Ng==', 'N2E4NTAwODMwOTliNGNkYTRjZjg3N2ZiNzg4NmYxMmY6MTY4MDYzOTQ3OA==', 'N2E4YTBjZDZlNTlhYTdmMGMwOWY2ODU5ZGU1N2E2YzU6MTY4MDYzOTQ3OQ==', 'N2E4ZDMyMzU1NGQ4OTFiMmQzZDhlMDE5MThkMzdjMDE6MTY4MDYzOTQ4MQ==', 'N2E5NTNjYzhlMDNjMmRlMjFlMzQyNDNmMmMyOTUwZDQ6MTY4MDYzOTQ4Mw==', 'N2E5NzQwMTMyYzQyNTdiMWYwNzA3ZjI1MTEzYTA4MDM6MTY4MDYzOTQ4NQ==', 'N2E5YTUyYmRlZGUyNzk1YWNjZmFiZmM4ODhmNTBjNTU6MTY4MDYzOTQ4Ng==', 'N2E5YzRjZjg0NzQ1NjgwZDdkZjYzMmM3Y2VkMzE5MGU6MTY4MDYzOTQ4OA==', 'N2FhMDJjYjUyN2Q4ZjY3NjkwZTIwMGNjZWY5YTEyOTY6MTY4MDYzOTQ4OQ==', 'N2FhMGIwODZjZDFhOGJiNDllMjQ5MThlOTBmN2I5ZjA6MTY4MDYzOTQ5MQ==', 'N2FhNWYwNzIzMGRjYjI1MTQ0ZTZlMDgxMmFkOTdkNGU6MTY4MDYzOTQ5Mw==', 'N2FhNjU3MGI2YmYyMzlmN2I0ZWFmNjQxNzE2ZTRkMzk6MTY4MDYzOTQ5NQ==', 'N2FhNjgwODJjMWQ1ZmQyYWVkZDMwOWVkOWMzMTNlYmY6MTY4MDYzOTQ5Ng==', 'NTQzNWMzZDYwYzIwOGI2MTJlNzZlNDg5MDQyZGNiMDU6MTY4MDYzOTQ5OA==', 'NTQzYWQ2ODgwMTJlOTVhNjZkOGZkYmE5ZDczZjY5NjM6MTY4MDYzOTUwMA==', 'NTQ0NzcxZjUxN2FmZTlmNGQ4N2FhMWI3OWQ5MWQ3NWU6MTY4MDYzOTUwMQ==', 'NTQ1MDAyNDQ2NWJjMTllYTA0NDJiMDdmMWQwNDNhYTU6MTY4MDYzOTUwNA==', 'NTQ1MDVkYWY4OTEyZGRmYjYwNWYwZDc0ZDFhZWJmZWE6MTY4MDYzOTUwNg==', 'NTQ1NGQ0ZjQ5ZjBjYTM2ZDY5NzVlZWQ4Mzg0OTRlMzI6MTY4MDYzOTUwOA==', 'NTQ1NGY4NzU1MzRlZGQ2OGFmNmI1ODY5MWI5MWEzMDQ6MTY4MDYzOTUxMA==', 'NTQ1NjcwZmJlZDc0MDMxOTExNzhjYWMwNjQ1ODI2MmI6MTY4MDYzOTUxMQ==', 'MTU1YzAyZjE1Y2I1YTIxZTcxMzJmNWNmZDczYTlhMWQ6MTY4MDYzOTUxMw==', 'MTU1Y2NmMTA4ZGM1NWY3MzQ5MjhhNzQwMWUwMTc0MGQ6MTY4MDYzOTUxNA==', 'MTU1ZjZhMGE3MGEyZWYxNzgyNjM4NmY5M2Q0ODBkOTU6MTY4MDYzOTUxNg==', 'MTU2MjUwOGZjMjc1MGUzYWY0NGI2MzlhNDBjN2FkZDU6MTY4MDYzOTUxNw==', 'OTY0YzNkY2I3ODhkYmU3M2U5NjUwODRjYWVjYTRhYWM6MTY4MDYzOTUxOQ==', 'OTY0ZDBhZDRlOTM3ZDkxNTY3YzQ1ZWRmN2Q5MDZmOGM6MTY4MDYzOTUyMA==', 'OTY0ZWM5MWE5MTZjNTQwNzY4OWYyYjlkNzdmNzk5NGI6MTY4MDYzOTUyMg==', 'OTY1MjEyMmNhYTk4NGViMjZiZWZiMjZkMjg2YTczNDM6MTY4MDYzOTUyNA==', 'OTY1MmY5NjJkMmViMTYzMTU5ZjU2ZGJkZGVmNWRhM2M6MTY4MDYzOTUyNQ==', 'OTY1NWJkMWU4YmI5YThkOWVjMGNiYjEyYmY5YWMwM2Q6MTY4MDYzOTUyNw==', 'ZDY4ODY0MWQ0MGJkYmY0NjBjZjcyMzIwZTRmNWYyZGQ6MTY4MDYzOTUyOA==', 'ZDY4YjI4ZmE2NmY1N2E5ZGU1NzcxNTgzN2M4NDA0MjU6MTY4MDYzOTUzMA==', 'ZDY5NTFiZWU1OWVmYjdjYWRmZTZmOWQ0Yzc4ZTVmMmU6MTY4MDYzOTUzMg==', 'ZDY5NTQzYTU0OWQyNDAzNDViZDQ4OWI2MDcyZTAxMDI6MTY4MDYzOTUzMw==', 'ZDY5NWJjOTVjMzBmYTQyMGE3YTVmNGQxZDQwOTZiZGE6MTY4MDYzOTUzNQ==', 'ZDY5ZGY0OWVlYjViOWVjOWQwMjhlYzI2ZmE0MjkxOTk6MTY4MDYzOTUzNw==', 'ZDZhODI1ZjU1NTU5Mzg4MTcxZjVjZDQ5YjAwZWIyYTM6MTY4MDYzOTUzOA==', 'ZDZhODM5YmZiY2Y3NmVjOWI2MDJlMWM5NDQ3MjEzOGQ6MTY4MDYzOTU0MA==', 'ZDZhZDIwM2U0MjI1MDU3MDZmMDdiMjhmMGYzNzYwZGQ6MTY4MDYzOTU0Mg==', 'ZDZhZDQ4NDY1ZjVlMmE3ODMwYmE5NGVlMzMzYTQ5M2Q6MTY4MDYzOTU0NA==', 'NDkyMmVmY2JiMmUzYmE4NWY1NzVlMzdkMmQ4MDhkMmQ6MTY4MDYzOTU0Nw==', 'NDkyMzZkZDQ5NDI0YzEwMjIxZmMxZWY4OGE4Yzk2YzM6MTY4MDYzOTU0OQ==', 'NDkyNTk0MjQ0NzQwMWQyYzdlMDRhNmFiOWZlYmNkNGQ6MTY4MDYzOTU1MQ==', 'NDkyOWFhYTRiYWRiMTlkZTEyNzIwMmZhYjFiZDQ3NDc6MTY4MDYzOTU1Mg==', 'NDkyOWYxNjJhMDY5MmIyZTY0ZTZmMjZiOTc2NjYyNGY6MTY4MDYzOTU1NA==', 'MDk5MTM4NjBiOGI2NDZkMDc2NzVhMTBmZTU2MWE1NTc6MTY4MDYzOTU1Ng==', 'MDk5MjMzNzg5MTdmMmRlNjAyMjYxNDU3ZmNjOTEzYjE6MTY4MDYzOTU1Nw==', 'MDk5NWIzZDdiN2RlOGI2YjJjM2ZkNjhkZDBhNjkzMTg6MTY4MDYzOTU1OA==', 'MDk5ZGExNWQ1NzMyOGIzNjg3MjEzZmZkMmRjYTRmY2U6MTY4MDYzOTU2MA==', 'MDk5ZmM0NWZjNGRkNTU1ZGM3ZTYwZWE4OTRmZWUxOGM6MTY4MDYzOTU2MQ==', 'MDlhMGIzNDdjZDVkMTFiOTdkMWIwYzMwOWRkNjM1ZjE6MTY4MDYzOTU2Mw==', 'MDlhMzk1MWVkM2MzM2VkN2U5NDk1MTkxYmQyMjQ5MWY6MTY4MDYzOTU2NQ==', 'MDlhOGRlZTEyMmYwOTkzOTdiZWRiNDhjOTNhZjc0NzM6MTY4MDYzOTU2Nw==', 'MDlhYTE4MmRkMmFkMTY2M2E1YTllMWNhMTE0NTI5MGI6MTY4MDYzOTU2OQ==', 'YjliMTg3OTE4ZjQ5YTcyNDc3MDNjYTY0ZDJkMjMxNmQ6MTY4MDYzOTU3MQ==', 'YjliOTdmYjk1YzI4ZDgxNDIzOGI5OGJhZTJmMjRmOGU6MTY4MDYzOTU3Mg==', 'YjliOWY1ZWNlZDdjYzY3NTBjOGJlOTAzZDExZjM3NzY6MTY4MDYzOTU3NA==', 'YjliOWZjMTY2NWI0ZTU5Nzc5ZWE5YTgwYjRmMGQzN2Q6MTY4MDYzOTU3Ng==', 'YjliY2I5MDg3YTJkNTI4YzBhMTJmYzllNjA5ZWMxYjI6MTY4MDYzOTU3OA==', 'YjliZjAzNDM4MWFkODg4NmYyMGYyZmQyNTNiN2EzOGI6MTY4MDYzOTU3OQ==', 'YjljMTI2NmIwY2ZjMTc4YWQ0MmI0NGU0MDFiOTM2Y2Q6MTY4MDYzOTU4MQ==', 'YjljMjk1YWNlNGQzODkxOTFkMTVlNGU4YWY1MTExNWY6MTY4MDYzOTU4Mg==', 'YjljNDg2YzRiYmZmNzFmNjJiZDdiMTc0YWQwNjczODg6MTY4MDYzOTU4NA==', 'YjljNTY1M2EwNjUzNDBhM2VjMTUxZDcwNjlhMmIxNGQ6MTY4MDYzOTU4Ng==', 'YjljNTdhM2Q1MTZmODMwOTNkMWZlMTRhYWM3YzE2ZmM6MTY4MDYzOTU4OA==', 'YjljNTkxNTFmYzEzZTlmYWJmYTU2MmE5OTdmOWZiNDk6MTY4MDYzOTU5MA==', 'YjljODFhNjhjYjViZDk3NDFhNTA1OGY4ZGVhNjU2ZDY6MTY4MDYzOTU5Mg==', 'YjljOTMwNTFhYmMxNjFkMjY0OTliNWI5OTI3Yzc4ZDg6MTY4MDYzOTU5NA==', 'YjljOWFkY2M4NzA3Yzg3YmNlMjlhODdmNTViNjYzMWY6MTY4MDYzOTU5Ng==', 'YjljZGU5MmRiZDA3MWRiNDRjZGJkNzY1YTM4ZjEwNjg6MTY4MDYzOTU5OA==', 'ZjM4YmE5YjlhNmY4MTYwYTdkNjAxZTgxYWYwNjJjMmM6MTY4MDYzOTU5OQ==', 'ZjM5NmNjNmE1YjRjZGJkZGRiYjc3ODEzODRiY2M2MTY6MTY4MDYzOTYwMA==', 'ZjM5OGY5MzhmYjA5YjIzMTRkOTRhMTg2YmM3ODNlYjE6MTY4MDYzOTYwMw==', 'ZjM5Y2NiNGNkNjg1YzMzMWYxMmE5ZDZlODIzMDIzMDA6MTY4MDYzOTYwNQ==', 'ZjM5ZGU1ZGU5MDNhZTllODIyY2U2NGRmNzBmODQ3NDI6MTY4MDYzOTYwNw==', 'ZjNhNGM4MGE4ZWFlYmI4Zjg4ZmI0ODMyOTFhNzkxMmY6MTY4MDYzOTYwOQ==', 'ZjNhNWFiY2U1NmI0ZjhjNWYzZGI2N2MzNzhkOWYwYjA6MTY4MDYzOTYxMQ==', 'ZjNhZDgyYjQ0OWQ1ZjQ5NmUzMTZkNmM3YzVlN2U3MGQ6MTY4MDYzOTYxMw==', 'MjY4YzU0OGY0YjljMTMyM2MxNGRhMTJiZGJjOWFmYmI6MTY4MDYzOTYxNA==', 'MjY4ZWVhOWIyOWQ3ZGNmNzdmN2MyNTY5NzU0NGU0N2Q6MTY4MDYzOTYxNg==', 'MjY5MTYwOTQ5MjhkMTE2Y2NjNGU5YzA0MGM4ZjQwOWM6MTY4MDYzOTYxOA==', 'MjY5MjhkNGUwNmYwNzQxMDQ1ZjY2Njg2MDQ1MjIzOGQ6MTY4MDYzOTYxOQ==', 'MjY5MzQ1ZjMzYmUwYmFlYmE3MGJjOWJlNGIxNDRmZWY6MTY4MDYzOTYyMQ==', 'MjY5NGEzNjkwZjQ0MWI0OGY1NzM1Y2E1YWY2ODEzYzk6MTY4MDYzOTYyMw==', 'MjY5YzBiMTM1NGVlY2NhMzVmNWIzZTAxZTc2MmYxYTc6MTY4MDYzOTYyNQ==', 'NzI5MGU3Zjk3ZmU4ODQ2ODY1Y2ZhMjEzN2Q2YWY0MTY6MTY4MDYzOTYyNw==', 'NzI5MTE4NmI1YjgwZDY3OTkxY2RlZmMwNjhhN2UxM2U6MTY4MDYzOTYyOQ==', 'NzI5NjkwYTg2OGExMzQ2NjM4ZDY2ZTUxMWY3MGRmZGQ6MTY4MDYzOTYzMQ==', 'NzI5NzZjM2UzZDJkODBmYzJiN2VkMGExYjNjNjk0ZDA6MTY4MDYzOTYzMw==', 'NzI5N2ZhMmUyMTIwZDUyNDQ3MGM0MTgwYTcyMWFlNDc6MTY4MDYzOTYzNQ==', 'NzI5ZWZjMjk5ZmZmZWFhNjg2MWY2OTAwYThkZTVlYjU6MTY4MDYzOTYzNg==', 'NzJhMDIwMWVjZDk0MzI0ODM2MjgyMzU0YTk5MmI0ZWQ6MTY4MDYzOTYzOA==', 'NWE1YzU1YTZhNDAyZDM4YTgzNzNjZDVkNmM0MTE4MmU6MTY4MDYzOTY0MA==', 'NWE1ZjM4MjI2MGFkZmY4ODQ4N2Q0ZTA0MGIwZDZkNGY6MTY4MDYzOTY0Mg==', 'NWE2MzdiMmIwMjlmNTJkZmUyYTE1NDAyZWFmZjRlZGY6MTY4MDYzOTY0NA==', 'NWE3MzNhZjFhNmI4NmQ0ODlhNDRmNWUzZjU0OGJlYTk6MTY4MDYzOTY0Ng==', 'NWE3NjU1N2VmZDFlOWQ3MTNhNTM4NGYzZjIwMDdjNzY6MTY4MDYzOTY0OA==', 'NWE3Nzg1OWE0YTQ2NTExNTUwMzNlNjJiYzBlMzZiZGY6MTY4MDYzOTY0OQ==', 'NWE3YzAxNzU2NmEyODNmMWJmYjQ2YzJlMGE0NDVkNmM6MTY4MDYzOTY1MQ==', 'NWE3ZmUxNzFmMGIxYzI4ZmMxNmY3YWVjMzkzN2EzZDU6MTY4MDYzOTY1Mw==', 'OGM2ZWFkZmJkY2Q1YjliNTU2NjhmZWExMzZiOTJiMzE6MTY4MDYzOTY1NQ==', 'OGM3MDVhOWZlZDhiOGNiZmZlMWNkYTIzNDU4NGMwNmU6MTY4MDYzOTY1Nw==', 'OGM3NDRkMWI1NGJjNWQ5ZmU1YTcxOWQ1OGQwOTljNzI6MTY4MDYzOTY1OQ==', 'OGM3NTZhYjVjNjdmYTZjNThlNjAxMjBiZDYxYTYwYTg6MTY4MDYzOTY2MQ==', 'OGM3N2FkNDZjNjlhOTM4ODc0ODFiZGQxNmY1NGQ2ODA6MTY4MDYzOTY2Mw==', 'OGM3N2ZlZGMwMDg2ZDYwZjk3NTc0YTYwODkzNGU5NmM6MTY4MDYzOTY2NQ==', 'OGM3ZDBhYzc4N2M0N2FkZWQ4NjM0YWI4OGUwMjNjNzI6MTY4MDYzOTY2Nw==', 'OGM3ZDFiNzgxZThkMjM1OWVmM2NlZjBjMTA2OTdiNzc6MTY4MDYzOTY2OQ==', 'OGM3ZTA0MjI1MTM1MGQ2OTBmYjMwMzgzMjJkYjQzNmU6MTY4MDYzOTY3MQ==', 'YTMwNWVlYmY2YmRjM2I3MWVkZGU2MjQ1NDcwZTdjYTA6MTY4MDYzOTY3Mw==', 'YTMxODRiZjg0NjFhOGFjYjE5MzM1ZGY3NTMzNTc2NDk6MTY4MDYzOTY3Ng==', 'YTMxYjg5MTVhM2I2NzkwZjI4M2IxZWQwMTBlNmEyMmU6MTY4MDYzOTY3OA==', 'YTMxZWU2MzI4Y2FiZTFlODhlNDRhZDk1YTk1N2RiMWQ6MTY4MDY0MDU0NQ==', 'YTMxZjEzNTlmMjY3NTdiNDU4YWY2MjQ2OWVmMTM2NjM6MTY4MDY0MDU0Ng==', 'YTMyMjA2ZmI0ZDEwOTc0OWM5OGZjODU5MTQ1MGM5ZmQ6MTY4MDY0MDU0OA==', 'YTMyMjZlZGE5Y2VhMjQwMTE0NGZjMGI1NTQxZmUzMTQ6MTY4MDY0MDU0OQ==', 'YTMyYjY0M2YxMGRlYjYxZTgxOWQwZTg0ZTIzMzdjOTA6MTY4MDY0MDU1MQ==', 'YTMyZWVmZTUyODUyZTU3MzVlMzk2ZmM1ZjBkMzAwN2Y6MTY4MDY0MDU1Mg==', 'YTMzMTg5MzAzZjU1ODhiMGMxMzhlN2VkMDE1YTEwNDg6MTY4MDY0MDU1NA==', 'YTMzNzI1MWYxNzM2NjFlYTFiM2I5Mzg1NWU4YTU4YzY6MTY4MDY0MDU1NQ==', 'ZDAyNzIwZDJhZWFiYTdlNTJiYjU3OTVjMTQyNzY0ZGQ6MTY4MDY0MDU1Ng==', 'ZDAyN2VmYjVkNTkwZDUyNWZkOTljMDcwOTFjNDU2MWM6MTY4MDY0MDU1OA==', 'ZDAyYzhmNjZkNTY3MmFhYTI2YWMwMWQ3ODUyNzU0MTk6MTY4MDY0MDU1OQ==']
    #
    # vt_client = vt.Client(anal.apikeylist[0])
    #
    # i = 0
    # for analysisId in analysisIds:
    #     while True:
    #         vt_report = vt_client.get_object("/analyses/{}", analysisId)
    #         print(vt_report.status)
    #         if vt_report.status == "completed":
    #             # vt_client.close()
    #             vt_result = vt_report.stats["malicious"] / (
    #                         vt_report.stats['undetected'] + vt_report.stats["malicious"])
    #             print(str(i)+' out of ' + str(len(analysisIds))+' : ' + str(analysisId) + '---->' + str(vt_result))
    #             i = i + 1
    #             break
    #         time.sleep(30)
    #
    # vt_client.close()

    # input_path = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/VirusShare_000a86a05b6208c3053ead8d1193b863'
    # fbytes = open(input_path, "rb").read()
    # # print(fbytes)
    #
    # testperse = lief.parse(fbytes)
    # print(len(testperse.segments))
    #
    # for seg in testperse.segments:
    #     print(seg)
    #
    # print('-----------------------------------------------------------------------------------------------------------')
    # modBytes = p.elf_overlay_append(fbytes)
    # # print(modBytes)
    # new_fparsed = lief.parse(modBytes)
    #
    #
    #
    # for s in new_fparsed.sections:
    #     print(s)
    #
    # builder = lief.ELF.Builder(new_fparsed)
    # builder.build()
    # ####new_fname = fname.replace(".exe", "_m.exe")
    # new_fname = "/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/perturbedElf"
    # builder.write(new_fname)

    # checkElfFormat()

    # transferOverSCP()

    AKMVG()

    # list_malware_names('/home/infobeyond/workspace/VirusShare/elfMalwares/','/home/infobeyond/workspace/VirusShare/elfMalwaresList')



