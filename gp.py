import pickle

import perturbation as p
import analysis as anal
import os
import sys
import lief
import time
import ssdeep
import random
import numpy as np
import json
# from numba import jit, cuda

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)
runningStatus = {}

# pertlist = ['overlay_append', 'upx_pack', 'upx_unpack', 'remove_signature', 'remove_debug', 'break_optional_header_checksum', 'inject_random_codecave', 'section_rename', 'pert_dos_stub', 'pert_bin_name', 'pert_optional_header_dllchlist', 'pert_optional_header_dllch', 'pert_rich_header', 'pert_dos_header', 'section_add', 'section_append']
# pertlist = ["overlay_append", "upx_pack", "upx_unpack", "inject_random_codecave", "section_rename", "pert_dos_stub",
#             "pert_optional_header_dllchlist", "pert_rich_header", "pert_dos_header", "section_add", "section_append",
#             "pert_optional_header", "pert_coff_header", "pert_data_directory"]
# pertlist = ["overlay_append","upx_pack","upx_unpack", "inject_random_codecave","section_rename","pert_dos_stub","pert_optional_header_dllchlist"
#             ,"pert_rich_header","pert_dos_header","section_add","pert_optional_header","pert_coff_header","pert_data_directory"]

###### Perturbation lists for PE executables
# pertListActive = ["overlay_append", "upx_pack", "upx_unpack", "inject_random_codecave", "section_rename", "pert_dos_stub",
#             "pert_rich_header", "pert_dos_header", "section_add",
#             "pert_optional_header", "pert_coff_header", "pert_data_directory"]

###### Perturbation lists for ELF executables
pertListActive = ["elf_overlay_append",
                "elf_upx_pack",
                "elf_upx_unpack",
                "elf_inject_random_codecave",
                "elf_section_rename",
                "elf_section_add",
                "elf_section_append",
                "elf_segment_add",
                "elf_program_header_table",
                "elf_segment_append",
                "elf_imports_append"]

one_time = ['upx_unpack', 'upx_pack', 'break_optional_header_checksum', 'remove_signature', 'remove_debug']

pickleSaveDirectory = '/home/infobeyond/workspace/VirusShare/AKMVG/elfMalwareGASaved/'
# pickleSaveDirectory = '/home/infobeyond/workspace/VirusShare/AKMVG/peMalwareGASaved/'

def difference(fbytes1, fbytes2):
    hash1 = ssdeep.hash(fbytes1)
    hash2 = ssdeep.hash(fbytes2)
    return 100 - ssdeep.compare(hash1, hash2)


class origin:
    def __init__(self, fname, fbytes, gnum, name, scanner):
        self.name = fname
        self.fbytes = fbytes
        self.vt_api_count = 0
        self.cuckoosig = anal.get_cuckoo_report(fname)
        self.md5 = anal.send_malware_scan(fbytes, apikeylist[self.vt_api_count], self)
        self.vt_result, vt_report = anal.get_malware_analysis(self.md5, self, fbytes)
        self.vt_dlist = "test"
        self.generation_number = gnum
        self.nameWithoutPath = name
        self.scoring_system = scanner #'malonv' #---- vt or jotti or malconv
        #self.vt_dlist = [data for data in vt_report["data"]["results"].keys() if vt_report["data"]["results"][data]["category"] == 'malicious']
        # print (self.vt_dlist)


class Chromosome:
    def __init__(self, fbytes):
        self.fbytes = fbytes
        self.pert = []
        self.functional = None
        self.vt_result = None
        self.diff = None
        # self.vt_report = None
        self.vt_dlist = None
        self.score = 0
        self.one = []
        self.pert_score = 0
        self.vtscore = 0
        self.prev_pert = []
        self.fname = None
        self.md5 = None
        self.nameWithoutPath = None


    def perturb(self, chosen_pert, initial=False):
        self.pert = chosen_pert
        fbytes = b''
        for pert in chosen_pert:
            if(pert == 'overlay_append'):
                fbytes = p.overlay_append(self.fbytes)
            elif (pert == 'upx_pack'):
                fbytes = p.upx_pack(self.fbytes)
            elif (pert == 'upx_unpack'):
                fbytes = p.upx_unpack(self.fbytes)
            elif (pert == 'inject_random_codecave'):
                fbytes = p.inject_random_codecave(self.fbytes)
            elif (pert == 'section_rename'):
                fbytes = p.section_rename(self.fbytes)
            elif (pert == 'pert_dos_stub'):
                fbytes = p.pert_dos_stub(self.fbytes)
            elif (pert == 'pert_optional_header_dllchlist'):
                fbytes = p.pert_optional_header_dllchlist(self.fbytes)
            elif (pert == 'pert_rich_header'):
                fbytes = p.pert_rich_header(self.fbytes)
            elif (pert == 'pert_dos_header'):
                fbytes = p.pert_dos_header(self.fbytes)
            elif (pert == 'section_add'):
                fbytes = p.section_add(self.fbytes)
            elif (pert == 'section_append'):
                fbytes = p.section_append(self.fbytes)
            elif (pert == 'pert_optional_header'):
                fbytes = p.pert_optional_header(self.fbytes)
            elif (pert == 'pert_coff_header'):
                fbytes = p.pert_coff_header(self.fbytes)
            elif (pert == 'pert_data_directory'):
                fbytes = p.pert_data_directory(self.fbytes)
            elif (pert == "elf_overlay_append"):
                fbytes = p.elf_overlay_append(self.fbytes)
            elif (pert == "elf_upx_pack"):
                fbytes = p.elf_upx_pack(self.fbytes)
            elif (pert == "elf_upx_unpack"):
                fbytes = p.elf_upx_unpack(self.fbytes)
            elif (pert == "elf_inject_random_codecave"):
                fbytes = p.elf_inject_random_codecave(self.fbytes)
            elif (pert == "elf_section_rename"):
                fbytes = p.elf_section_rename(self.fbytes)
            elif (pert == "elf_section_add"):
                fbytes = p.elf_section_add(self.fbytes)
            elif (pert == "elf_section_append"):
                fbytes = p.elf_segment_append(self.fbytes)
            elif (pert == "elf_segment_add"):
                fbytes = p.elf_segment_add(self.fbytes)
            elif (pert == "elf_program_header_table"):
                fbytes = p.elf_program_header_table(self.fbytes)
            elif (pert == "elf_segment_append"):
                fbytes = p.elf_segment_append(self.fbytes)
            elif (pert == "elf_imports_append"):
                fbytes = p.elf_imports_append(self.fbytes)

            if len(fbytes) == 0:
                print(len(fbytes))
            else:
                self.fbytes = fbytes

            # self.fbytes = eval("p." + pert + "(self.fbytes)")
            # time.sleep(5)




    def past_scoring(self, diff, vt_result, functional):
        self.functional = functional
        self.vt_result = vt_result
        self.diff = diff
        if functional:
            self.score = 50 + diff + (100 - vt_result * 100)
            self.vtscore = 50 + diff + (100 - vt_result * 100)
            self.pert_score = 0
        else:
            self.score = 0

    def scoring(self):
        if self.functional:
            self.score = 40 + (100 - self.vt_result) + self.diff
        else:
            self.score = 100 - self.vt_result + self.diff

        # print (self.score)

    def scoring_without_vt(self, diff, functional):
        self.functional = functional
        self.diff = diff
        if functional:
            # self.score = 50 + diff + (100 - vt_result*100)
            if self.vtscore != 0:
                self.score = self.vtscore = self.vtscore + self.pert_score + diff
            else:
                self.score = 50 + self.pert_score + diff
        else:
            self.score = 0


class GP:
    def __init__(self, fbytes, population, pertnum, output_path, skip, original):
        random.seed(None)
        self.original = original
        self.population = []
        self.size = population
        self.pertnum = pertnum
        self.output_path = output_path
        self.skip = skip

        for i in range(population):
            chosen_pert = random.sample(pertListActive, self.pertnum)
            member = Chromosome(fbytes)
            member.perturb(chosen_pert, initial=True)
            self.population.append(member)

        self.generationnum = 1

    def score(self, original, generation_no):
        i = 1
        chosen_idx = random.randrange(apilen)

        ## save executables in disk
        for pop in self.population:
            if pop.vt_result != None:
                i += 1
                continue

            variantFileNameWithoutPath = "_g" + str(generation_no) + "_p" + str(i)
            variantFileName = original.name + variantFileNameWithoutPath
            # p.build_lief_name(pop.fbytes, original.name, variantFileName)
            pop.fname = variantFileName
            pop.nameWithoutPath = variantFileNameWithoutPath
            pop.diff = difference(original.fbytes, pop.fbytes)
            pop.md5 = anal.send_malware_scan(pop.fbytes, apikeylist[(chosen_idx + i) % apilen], original)
            i += 1

        ## obtain cuckoo signatures running saved binary files on cuckoo server
        for pop in self.population:
            if pop.functional != None:
                continue
            pop.functional = anal.func_check(original.cuckoosig, pop.fbytes)

        ## obtain detection score running saved binary on malware scanners
        for pop in self.population:
            if pop.vt_result != None:
                continue
            pop.vt_result, vt_report = anal.get_malware_analysis(pop.md5, original, pop.fbytes)
            pop.scoring()
            # os.remove(pop.fname)

        self.population = sorted(self.population, key=lambda pop: pop.score, reverse=True)

    # @jit(target_backend='cuda')
    def selection(self, original, generation_no):
        self.score(original, generation_no)
        self.population = self.population[:self.size]
        ## obtain detection score running saved binary on malware scanners

    # @jit(target_backend='cuda')
    def mutate(self, prob):
        populationlist = list(self.population)
        for pop in populationlist[:int(self.size / 2)]:  # self.population:
            # generate new mutant chromosome
            new_pop = Chromosome(bytes(pop.fbytes))
            new_pop.prev_pert = list(pop.prev_pert)
            new_pop.prev_pert.append(list(pop.pert))
            nchosen_pert = random.sample(pertListActive, self.pertnum)
            new_pop.perturb(nchosen_pert)

            if new_pop.fbytes == pop.fbytes:
                new_pop.pert_score = pop.pert_score
                new_pop.vtscore = pop.vtscore
                new_pop.functional = pop.functional

            self.population.append(new_pop)

        for pop in populationlist[int(self.size / 2):]:
            if random.random() < prob:
                new_pop = Chromosome(bytes(pop.fbytes))
                # new_pop.pert_score = pop.pert_score
                # new_pop.vtscore = pop.vtscore
                new_pop.prev_pert = list(pop.prev_pert)
                new_pop.prev_pert.append(list(pop.pert))

                nchosen_pert = random.sample(pertListActive, self.pertnum)
                new_pop.perturb(nchosen_pert)

                if new_pop.fbytes == pop.fbytes:
                    new_pop.pert_score = pop.pert_score
                    new_pop.vtscore = pop.vtscore
                    new_pop.functional = pop.functional

                self.population.append(new_pop)

    def pickleDump(self):
        savedFileName = pickleSaveDirectory + str(self.original.nameWithoutPath) + \
                        '_' + str(self.original.generation_number) + '_' + str(self.size)
        with open(savedFileName, 'wb') as saved_file:
            pickle.dump(self, saved_file)

    def printStoreResults(self, end_time):
        print("* " + str(self.generationnum) + " generation: 5 best populations\n")
        for k in range(self.size):
            print("Generation - " + str(self.generationnum) + ", Population - " + str(k + 1))
            print("Fitness Score (FS): " + str(round(self.population[k].score, 2)))
            print("Malconv Detection Rate (DR): " + str(round(self.population[k].vt_result * 100, 2)))
            print("SSDEEP Score (SS): " + str(self.population[k].diff))
            print("Malware Functionality Preserved (Cuckoo Analysis): " + str(self.population[k].functional))
            print("Applied Perturbations: " + str(self.population[k].pert) + str(self.population[k].prev_pert))
            # print("Previously applied perturbations: " + str(self.population[k].prev_pert))
            print("")
            ## write on the file
            with open(self.output_path, "a") as wf:
                wf.write(str(self.original.nameWithoutPath) + ";"
                         + str(self.population[k].nameWithoutPath) + ";"
                         + 'malconv' + ";"
                         + str(self.original.generation_number) + ";"
                         + str(self.size) + ";"
                         + str(self.generationnum) + ";"
                         + str(k) + ";"
                         + str(end_time) + ";"
                         + str(self.population[k].functional) + ";"
                         + str(self.population[k].diff) + ";"
                         + str(self.population[k].vt_result) + ";"
                         + str(self.population[k].score) + ";"
                         + str(self.population[k].prev_pert) + ","
                         + str(self.population[k].pert) + " \n")
            # save on file to resume later
            self.pickleDump()



    def generation(self, original):
        #time.sleep(10)

        if self.generationnum == 1:
            start_time = time.time()
            self.score(original, 1)
            end_time = time.time() - start_time
            self.printStoreResults(end_time)

        for i in range(original.generation_number):
            if (i+1) <= self.generationnum:
                continue

            self.generationnum = i+1
            start_time = time.time()
            self.mutate(0.3)
            self.selection(original, self.generationnum)
            end_time = time.time() - start_time

            self.printStoreResults(end_time)

    def execute(self):
        self.generation(self.original)
        pass