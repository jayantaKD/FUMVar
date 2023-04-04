import sys
import os
from argparse import ArgumentParser
import gp
import analysis as anal

import logging
from malconv_nn import malconv
import shutil



def AKMVG():
    skip = 20
    perturbation = 1
    output_path = '/home/infobeyond/workspace/VirusShare/AKMVG/output1'
    input_directory = '/home/infobeyond/workspace/VirusShare/AKMVG/malwares'
    # input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_20130711'
    # input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_High_DR'
    # input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_Low_DR'
    # generationList = [50, 100, 150, 200, 250, 300]
    # populationList = [10, 50, 100]

    generationList = [50]
    # generationList = [10, 15, 20, 25, 30]
    # populationList = [2, 5, 10, 15, 20]
    populationList = [50]

    with open(output_path, "a") as wf:
        wf.write("Original_File_Name" + ";"
                 + "Variant_File_Name" + ";"
                 + "Scanner" + ";"
                 + "Total_Gen" + ";"
                 + "Total_Population" + ";"
                 + "Generation_No." + ";"
                 + "Population_No." + ";"
                 + "Delay" + ";"
                 + "Functional" + ";"
                 + "Ssdeep Score" + ";"
                 + "VT Score" + ";"
                 + "Fitness Score" + ";"
                 + "Perturbation" + " \n")

    files = ['VirusShare_ae6af24501520d8e9e069cf6e85fb87a',
             'VirusShare_16a6955696ef375f1efb1d371cd9928c',
             'VirusShare_c78120aa5124274b458ebbdce5cd60ce',
             'VirusShare_4625556d1816142a1f8250bed15a834e',
             'VirusShare_01db10a317194fe7c94a58fae14f787c',
             'VirusShare_c0785f417aaf685af51c1212a0aa955c',
             'VirusShare_a7a3dbf9dd16606262d647c7d5814be1',
             'VirusShare_f5a3a06c99e01b856e55b3a178cedd51',
             'VirusShare_e0f6ef60c2d34dd49042ed5b287ce087',
             'VirusShare_7926a3a1708da681d54dd1a6ea45be37',
             'VirusShare_7970c24a511a6e6ae6b7c21a2deb371e',
             'VirusShare_2c75605732e53ab5eda618bcc2a1042d',
             'VirusShare_8452649012c7f2546c71f71518a06812',
             'VirusShare_29748f96daca16266b9ded60531f916e',
             'VirusShare_cdcc63adaa351be416b61da0dffb2c2c',
             'VirusShare_9715bbe0c4f594da9bbd99d2887f2061',
             'VirusShare_fdbde2e1fb4d183cee684e7b9819bc13',
             'VirusShare_487abbadd74e843ddaa0da3af36769e5',
             'VirusShare_37435ddc3ff4a1b3d76139bf2ff2a76e',
             'VirusShare_cadb6eccee60be126c2725b561833c75',
             'VirusShare_55da827a2e1e53de9a99a5a7be8e6e80',
             'VirusShare_09d49c997fa5df14cbefd9b745e04acf',
             'VirusShare_e2c82a0891c23d5afc86cfd6115e6b7c',
             'VirusShare_d3367aef91417ee4991ed7680c0ca5df',
             'VirusShare_73555509028ef8d62f50b1a57ad3c809',
             'VirusShare_1e34b50b8af8dbeb750c291981428053']

    # files = ['VirusShare_7926a3a1708da681d54dd1a6ea45be37', 'VirusShare_55da827a2e1e53de9a99a5a7be8e6e80']

    # files = ['VirusShare_55da827a2e1e53de9a99a5a7be8e6e80',
    #     'VirusShare_09d49c997fa5df14cbefd9b745e04acf',
    #     'VirusShare_e2c82a0891c23d5afc86cfd6115e6b7c',
    #     'VirusShare_d3367aef91417ee4991ed7680c0ca5df',
    #     'VirusShare_73555509028ef8d62f50b1a57ad3c809',
    #     'VirusShare_1e34b50b8af8dbeb750c291981428053']

    # Multiple malware in the directory
    for filename in files:
        # Varying number of total generations
        for generation in generationList:
            # Varying number of initial population list
            for population in populationList:
                input_path = os.path.join(input_directory, filename)
                print("* Scanning original malware sample")
                fbytes = open(input_path, "rb").read()
                original = gp.origin(input_path, fbytes, generation, filename, 'malonv')

                print("\nOriginal file: " + input_path)
                print("VirusTotal detection rate: " + str(original.vt_result))
                print("")

                print("* Starting GP malware generation\n")
                print("* 1 generation\n")
                g = gp.GP(fbytes, population, perturbation, output_path, skip)
                g.generation(original, generation)
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
    inputDirectory = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/MalwareBazar_batch_01_PE/'
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

if __name__ == "__main__":
    logging.getLogger().disabled = True
    # PEmalwareCollection()
    list_malware_names()
