import sys
import os
from argparse import ArgumentParser
import gp
import analysis as anal

import logging
# logging.getLogger("Python").setLevel(logging.WARNING)
# logging.getLogger("Coding").setLevel(logging.WARNING)

if __name__ == "__main__":
    skip = 20
    perturbation = 1


    output_path = '/home/infobeyond/workspace/VirusShare/AKMVG/output1'

    input_directory = '/home/infobeyond/workspace/VirusShare/AKMVG/malwares'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_20130711'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_High_DR'
    #input_directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_Low_DR'
    #generationList = [50, 100, 150, 200, 250, 300]
    #populationList = [10, 50, 100]

    generationList = [10, 15, 20, 25, 30]
    populationList = [2, 5, 10, 15, 20]

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

    # Multiple malware in the directory
    for filename in os.listdir(input_directory):
        # Varying number of total generations
        for generation in generationList:
            # Varying number of initial population list
            for population in populationList:
                input_path = os.path.join(input_directory, filename)
                print("* Scanning original malware sample")
                fbytes = open(input_path, "rb").read()
                original = gp.origin(input_path, fbytes, generation, filename,'malonv')

                print("\nOriginal file: " + input_path)
                print("VirusTotal detection rate: " + str(original.vt_result))
                print("")

                print("* Starting GP malware generation\n")
                print("* 1 generation\n")
                g = gp.GP(fbytes, population, perturbation, output_path, skip)
                g.generation(original, generation)
                print('-----------------------------------------------------------------------------------------------')