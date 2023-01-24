import sys
import os
from argparse import ArgumentParser
import gp
import analysis

if __name__ == "__main__":
    parser = ArgumentParser()    
    parser.add_argument("-i", type=str, help="Path for binary input", dest="input_path", required=False)
    parser.add_argument("-o", type=str, help="Path for result", dest="output_path", required=False)
    parser.add_argument("-p", type=int, help="Number of population (default=4)", dest="population")
    parser.add_argument("-m", type=int, help="Number of perturbation per generation (default=4)", dest="perturbation")
    parser.add_argument("-g", type=int, help="Number of generation (default=100)", dest="generation")
    parser.add_argument("-s", type=int, help="Number of skip time for VirusTotal scan generation (default=5)", dest="skip")
    
    args = parser.parse_args()
    population = 10
    perturbation = 1
    generation = 100
    skip = 20
    #input_path = '/home/infobeyond/VirusShare/VirusShare_PE'
    #input_path = '/home/infobeyond/VirusShare/ELF_Linux_i386_x64_86/VirusShare_66dbd9c0bc312ebc2e09cbc9ba1c1dd7'
    input_path="D:\\AutoGenMalware\\Malware_Database\\VirusShare_x86-64_WinEXE_20130711\\VirusShare_00c28cee9c6874302982045b5faff846"
    #output_path = '/home/infobeyond/VirusShare/output1'
    output_path = "D:\\AutoGenMalware\\Malware_Database\\output"

    if args.population:
        population = args.population
    if args.perturbation:
        perturbation = args.perturbation
    if args.generation:
        generation = args.generation
    if args.skip:
        skip = args.skip
    if args.input_path:
        input_path = args.input_path
    if args.output_path:
        output_path = args.output_path
    
    print ("* Scanning original malware sample")
    fbytes = open(input_path,"rb").read()

    original = gp.origin(input_path,fbytes)

    with open(output_path, "a") as wf:
        wf.write("original file: "+input_path+"\nVT result: "+str(original.vt_result)+"\nVT detection list:"+str(original.vt_dlist)+"\n\n")
    print ("\nOriginal file: " + input_path)
    print ("VirusTotal detection rate: " + str(original.vt_result))
    print ("") 

    print ("* Starting GP malware generation\n")
    print ("* 1 generation\n")
    g = gp.GP(fbytes,population,perturbation,output_path,skip)
    g.generation(original,generation)
