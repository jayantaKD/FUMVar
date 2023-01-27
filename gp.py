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

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)

# pertlist = ['overlay_append', 'upx_pack', 'upx_unpack', 'remove_signature', 'remove_debug', 'break_optional_header_checksum', 'inject_random_codecave', 'section_rename', 'pert_dos_stub', 'pert_bin_name', 'pert_optional_header_dllchlist', 'pert_optional_header_dllch', 'pert_rich_header', 'pert_dos_header', 'section_add', 'section_append']

# pertlist = ["overlay_append", "upx_pack", "upx_unpack", "inject_random_codecave", "section_rename", "pert_dos_stub",
#             "pert_optional_header_dllchlist", "pert_rich_header", "pert_dos_header", "section_add", "section_append",
#             "pert_optional_header", "pert_coff_header", "pert_data_directory"]

# pertlist = ["overlay_append","upx_pack","upx_unpack", "inject_random_codecave","section_rename","pert_dos_stub","pert_optional_header_dllchlist"
#             ,"pert_rich_header","pert_dos_header","section_add","pert_optional_header","pert_coff_header","pert_data_directory"]

pertlist = ["overlay_append","upx_pack","upx_unpack", "inject_random_codecave","section_rename","pert_dos_stub","pert_optional_header_dllchlist"
             ,"pert_rich_header","pert_dos_header","section_add","pert_optional_header","pert_coff_header","pert_data_directory"]

# elf_pertlist = ["elf_overlay_append", "elf_upx_pack", "elf_upx_unpack", "elf_inject_random_codecave", "elf_section_rename", "elf_section_add", "elf_section_append"]

one_time = ['upx_unpack', 'upx_pack', 'break_optional_header_checksum', 'remove_signature', 'remove_debug']


def difference(fbytes1, fbytes2):
    hash1 = ssdeep.hash(fbytes1)
    hash2 = ssdeep.hash(fbytes2)
    return 100 - ssdeep.compare(hash1, hash2)


class origin:
    def __init__(self, fname, fbytes):
        self.name = fname
        self.fbytes = fbytes
        self.vt_api_count = 0
        self.cuckoosig = anal.get_cuckoo_report(fname)
        self.md5 = anal.send_malware_scan(fname, apikeylist[self.vt_api_count], self)
        self.vt_result, vt_report = anal.get_malware_analysis(self.md5, self)
        self.vt_dlist = "test"
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


    def perturb(self, chosen_pert, initial=False):
        self.pert = chosen_pert
        for pert in chosen_pert:
            self.fbytes = eval("p." + pert + "(self.fbytes)")
            #time.sleep(5)


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
    def __init__(self, fbytes, population, pertnum, output_path, skip):
        random.seed(None)
        self.population = []
        self.size = population
        self.pertnum = pertnum
        self.output_path = output_path
        self.skip = skip

        for i in range(population):
            chosen_pert = random.sample(pertlist, self.pertnum)
            member = Chromosome(fbytes)
            member.perturb(chosen_pert, initial=True)
            self.population.append(member)

        self.generationnum = 1

    def score(self, original):
        i = 1
        chosen_idx = random.randrange(apilen)
        for pop in self.population:
            if pop.vt_result != None:
                i += 1
                continue
            # p.build_lief(pop.fbytes,original.name)
            p.build_lief_name(pop.fbytes, original.name, (original.name + "_m" + str(i)))
            ####### pop.fname = original.name.replace(".exe", "_m" + str(i) + ".exe")
            pop.fname = original.name + "_m" + str(i)
            # print (pop.fname)
            pop.diff = difference(original.fbytes, pop.fbytes)
            pop.md5 = anal.send_malware_scan(pop.fname, apikeylist[(chosen_idx + i) % apilen], original)
            i += 1

        ck = 0
        for pop in self.population:
            if pop.functional != None:
                continue

            # for pop2 in self.population:
            #     if pop2 in self.population:
            #         if pop2.fname == pop.fname:
            #             continue
            #         if pop2.fbytes == pop.fbytes and pop2.functional != None:
            #             pop.functional = pop2.functional
            #             ck = 1
            # if ck == 1:
            #     ck = 0
            #     continue

            pop.functional = anal.func_check(original.cuckoosig, pop.fname)
            ########with open(self.output_path.replace(".txt", "_suc_rate.txt"), "a") as wf:
            # with open(self.output_path + "_suc_rate", "a") as wf:
            #     wf.write("prev_perturbation, perturbation, functionality: " + str(pop.prev_pert) + ", " + str(
            #         pop.pert) + ", " + str(pop.functional) + "\n")

        ck = 0
        for pop in self.population:
            if pop.vt_result != None:
                continue

            # for pop2 in self.population:
            #     if pop2 in self.population:
            #         if pop2.fname == pop.fname:
            #             continue
            #         if pop2.fbytes == pop.fbytes and pop2.vt_result != None:
            #             pop.vt_result = pop2.vt_result
            #             ck = 1
            # if ck == 1:
            #     ck = 0
            #     continue

            pop.vt_result, vt_report = anal.get_malware_analysis(pop.md5, original)
            #pop.vt_dlist = [data for data in vt_report["scans"].keys() if vt_report["scans"][data]["detected"] == True]
            #pop.vt_dlist = [data for data in vt_report["data"]["results"].keys() ifvt_report["data"]["results"][data]["category"] == 'malicious']

            pop.scoring()
        self.population = sorted(self.population, key=lambda pop: pop.score, reverse=True)

    def selection(self, original):
        self.score(original)
        self.population = self.population[:self.size]

    def mutate(self, prob):
        populationlist = list(self.population)
        for pop in populationlist[:int(self.size / 2)]:  # self.population:
            # generate new mutant chromosome
            new_pop = Chromosome(bytes(pop.fbytes))
            new_pop.prev_pert = list(pop.prev_pert)
            new_pop.prev_pert.append(list(pop.pert))
            nchosen_pert = random.sample(pertlist, self.pertnum)
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

                nchosen_pert = random.sample(pertlist, self.pertnum)
                new_pop.perturb(nchosen_pert)

                if new_pop.fbytes == pop.fbytes:
                    new_pop.pert_score = pop.pert_score
                    new_pop.vtscore = pop.vtscore
                    new_pop.functional = pop.functional

                self.population.append(new_pop)

    def generation(self, original, gnum):
        self.score(original)
        # self.score_without_vt(original)

        with open(self.output_path, "a") as wf:
            wf.write("Generation No." + ";" + "Population No." + ";" + "Functional" + ";"
                     + "Ssdeep Score" + ";" + "VT Score" + ";"
                     + "Fitness Score" + ";" + "Perturbation" + " \n")

        with open(self.output_path, "a") as wf:
            wf.write(str(original.name) + ";" + "0" + ";" + "0" + ";" + "True" + ";" + "0" + ";" + str(original.vt_result) + ";"
                     + "0" + ";" + "" + " \n")

        for i in range(gnum):
            self.generationnum = i+1
            print("* " + str(self.generationnum) + " generation\n")
            for k in range(self.size):
                print("* Member " + str(k))
                print("Malware Functionality: " + str(self.population[k].functional))
                print("VirusTotal detection rate: " + str(self.population[k].vt_result))
                print("Applied perturbations: " + str(self.population[k].pert))
                print("Previously applied perturbations: " + str(self.population[k].prev_pert))
                print("")

                with open(self.output_path, "a") as wf:
                    wf.write(str(original.name) + ";" + str(self.generationnum) + ";" + str(k) + ";" + str(self.population[k].functional) + ";"
                             + str(self.population[k].diff) + ";" + str(self.population[k].vt_result) + ";"
                             + str(self.population[k].score) + ";" + str(self.population[k].prev_pert) + "," +
                             str(self.population[k].pert) + " \n")

            start_time = time.time()
            self.mutate(0.3)
            self.selection(original)
            end_time = time.time() - start_time

