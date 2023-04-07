# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import json
import os
import shutil
import subprocess
import sys
import time
import random
import lief
import vt
import numpy as np

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'small_dll_imports.json'), 'r'))

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


def virusShareDatabaseExplore():
    # directory = 'D:\\AutoGenMalware\\Malware_Database\\VirusShare_00449'
    directory = 'D:\\AutoGenMalware\\Malware_Database\\ELF_Linux_i386_x64_86'

    # iterate over files in
    # that directory
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if lief.is_elf(f):
            binary = lief.ELF.parse(f)
            if binary.header.identity_os_abi == lief.ELF.OS_ABI.LINUX \
                    and (binary.header.machine_type == lief.ELF.ARCH.x86_64):
                print(binary.header.identity_os_abi)
                print(binary.header.machine_type)
                print(f)
                print('---------------------------')
                # shutil.move(f, "D:\\AutoGenMalware\\Malware_Database\\ELF_Linux_i386_x64_86\\" + filename)

        if lief.is_pe(f):
            binary = lief.PE.parse(f)
            if binary.header.machine == lief.PE.MACHINE_TYPES.I386 \
                    or binary.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                print(binary.header.machine)
                print(f)
                print('---------------------------')
                # shutil.move(f, "D:\\AutoGenMalware\\Malware_Database\\PE_AMD64_I386\\" + filename)


def experimentalExplore():
    # filename = 'hello_lief.bin'
    filename = 'hello_lief_aarch64.bin'
    targetFilename = 'VirusShare_1b5ca91678e869805944a203f856b810'
    f = os.path.join('C:\\Users\\jayan\\workspace\\LIEF-master\\tests\\elf', filename)
    target_f = os.path.join('D:\\AutoGenMalware\\Malware_Database\\ELF_Linux_i386_x64_86', targetFilename)

    # checking if it is a file
    if lief.is_elf(f):
        binary = lief.ELF.parse(f)
        target_binary = lief.ELF.parse(target_f)
        print('printing entry point')
        print(binary.header.entrypoint)
        print(target_binary.header.entrypoint)

        section = lief.ELF.Section(f".test.test", lief.ELF.SECTION_TYPES.PROGBITS)
        section.type = lief.ELF.SECTION_TYPES.PROGBITS
        section += lief.ELF.SECTION_FLAGS.EXECINSTR
        section += lief.ELF.SECTION_FLAGS.WRITE

        print(section.virtual_address)

        section = target_binary.add(section, loaded=True)

        print(section.virtual_address)
    else:
        print('Not a ELF file')


def vtExplore():
    file = "D:\\AutoGenMalware\\Malware_Database\\VirusShare_x86-64_WinEXE_20130711\\VirusShare_00c28cee9c6874302982045b5faff846"

    directory = 'D:\\AutoGenMalware\\Malware_Database\\ELF_Linux_i386_x64_86'

    for filename in os.listdir(directory):
        client = vt.Client("cf1fa7147c58038ef9615c5fbc4a2e4496193aef858af6fa9351632c21b1bdbb")
        fullname = os.path.join(directory, filename)

        with open(fullname, "rb") as f:
            analysis = client.scan_file(f)
            print(json.dumps(analysis.__dict__))

        while True:
            report = client.get_object("/analyses/{}", analysis.id)
            print(report.status)
            if report.status == "completed":
                print(json.dumps(report.__dict__))
                break
            time.sleep(30)
        client.close()


def test():
    filename = ""
    fbytes = open(filename, "rb").read()
    binary = lief.PE.parse(filename)


def overly_append(binary):
    l = 2 ** random.randint(5, 8)
    new_fbytes = binary + bytes([random.randint(255, 255) for _ in range(l)])
    print(new_fbytes)


def dos_header_pert(fbytes):
    fparsed = lief.parse(fbytes);
    NumberMin = 0x00;
    NumberMax = 0xFFFF
    fparsed.dos_header.initial_ip = random.randint(NumberMin, NumberMax)
    fparsed.dos_header.initial_relative_cs = random.randint(NumberMin, NumberMax)
    fparsed.dos_header.overlay_number = random.randint(NumberMin, NumberMax)
    fparsed.dos_header.oem_id = random.randint(NumberMin, NumberMax)
    fparsed.dos_header.oem_info = random.randint(NumberMin, NumberMax)
    print(fparsed.dos_header)


def dos_stub_pert(fbytes):
    fparsed = lief.parse(fbytes)
    perturbed_dos_stub = list(fparsed.dos_stub)
    sindex, eindex = tuple(sorted(random.sample([i for i in range(len(perturbed_dos_stub))], 2)))
    for i in range(sindex, eindex):
        perturbed_dos_stub[i] = random.randrange(0x00, 0xFF)

    beforePerturb = []
    for item in list(fparsed.dos_stub):
        beforePerturb.append(hex(item))
    print('PE malware variant DOS stub (before perturbation):')
    print(beforePerturb)
    afterPerturb = []
    for item in perturbed_dos_stub:
        afterPerturb.append(hex(item))
    print('')
    print('PE malware variant DOS stub (after perturbation of randomly chosen indexes - %d to %d):' % (
    sindex, eindex - 1))
    print(afterPerturb)
    print('');
    print('')
    print(fbytes)


def pert_optional_header(fbytes):
    fparsed = lief.parse(fbytes);
    print(fparsed.optional_header)
    pertFieldList = [fparsed.optional_header.sizeof_uninitialized_data, fparsed.optional_header.sizeof_initialized_data,
                     fparsed.optional_header.baseof_code, fparsed.optional_header.checksum,
                     fparsed.optional_header.sizeof_heap_reserve,
                     fparsed.optional_header.sizeof_stack_commit, fparsed.optional_header.win32_version_value,
                     fparsed.optional_header.major_linker_version,
                     fparsed.optional_header.major_image_version,
                     fparsed.optional_header.major_operating_system_version,
                     fparsed.optional_header.major_subsystem_version,
                     fparsed.optional_header.minor_image_version, fparsed.optional_header.minor_linker_version,
                     fparsed.optional_header.minor_operating_system_version,
                     fparsed.optional_header.minor_subsystem_version];
    idx = random.randrange(len(pertFieldList))
    if idx < 6:
        pertFieldList[idx] = random.randrange(0, 0xFFFFFFFF)
    else:
        pertFieldList[idx] = random.randrange(0, 0xFF)

    fparsed.optional_header.baseof_code = 0x89FF
    print(fparsed.optional_header)
    print()
    print()
    print()
    print()
    print(idx)


def pert_coff_header(fbytes):
    fparsed = lief.parse(fbytes);
    print(fparsed.header)
    fparsed.header.numberof_symbols = random.randrange(0x0, 0xFFFFFFFF)
    fparsed.header.time_date_stamps = random.randrange(0x0, 0xFFFFFFFF)
    fparsed.header.pointerto_symbol_table = random.randrange(0x0, 0xFFFFFFFF)

    print(fparsed.header)
    print(fbytes)


def pert_rich_header(fbytes):  # add rich header entry
    fparsed = lief.parse(fbytes)
    new_entry = lief.PE.RichEntry()
    new_entry.id = 102
    new_entry.build_id = 0x798f
    new_entry.count = 2
    fparsed.rich_header.add_entry(new_entry)


def pert_data_directory(fbytes):
    fparsed = lief.parse(fbytes)
    target = random.choice(fparsed.data_directories);
    print(target)
    target.rva = random.randrange(0x00, 0xFFFFFFFF)
    target.size = random.randrange(0x00, 0xFFFFFFFF)
    print(target)
    print()
    print()
    print(fbytes)


def pert_section_rename(fbytes):
    random.seed(None)
    length = random.randrange(1, 6)
    fparsed = lief.parse(fbytes)
    name = "." + ''.join(random.sample([chr(i) for i in range(97, 123)], length))
    targeted_section = random.choice(fparsed.sections)
    targeted_section.name = name

    # print('Name Vir. Size Vir. Add. Raw size Raw Add. Pointer to Reloc Characteristics')
    print('\n')
    for section in fparsed.sections:
        print(section)

    # print(targeted_section)
    print('\n\n')
    targeted_section.name = name
    # print(targeted_section)
    for section in fparsed.sections:
        print(section)
    print('\n\n')
    return fparsed


def pert_section_add(fbytes, seed=None):
    fparsed = lief.parse(fbytes);
    length = random.randrange(1, 6)
    new_section = lief.PE.Section("." + "".join(random.sample([chr(i) for i in range(97, 123)], length)))
    upper = random.randrange(128);
    L = 2 ** random.randint(5, 8);
    size = fparsed.optional_header.section_alignment
    new_section.content = [random.randint(0, upper) for _ in range(L)]
    new_section.virtual_size = size;
    new_section.virtual_address = max([s.virtual_address + s.virtual_size for s in fparsed.sections])
    fparsed.add_section(new_section, random.choice([lief.PE.SECTION_TYPES.BSS, lief.PE.SECTION_TYPES.DATA,
                                                    lief.PE.SECTION_TYPES.EXPORT, lief.PE.SECTION_TYPES.IDATA,
                                                    lief.PE.SECTION_TYPES.RELOCATION, lief.PE.SECTION_TYPES.RESOURCE,
                                                    lief.PE.SECTION_TYPES.TEXT, lief.PE.SECTION_TYPES.TLS_,
                                                    lief.PE.SECTION_TYPES.UNKNOWN, ]))
    print('\n')
    for section in fparsed.sections:
        print(section)
    return fparsed


def pert_section_append(fbytes, seed=None):
    fparsed = lief.parse(fbytes);
    targeted_section = random.choice(fparsed.sections)
    section_append_length = 2 ** random.randint(5, 8)
    available_size = targeted_section.size - len(targeted_section.content)
    if section_append_length > available_size:
        section_append_length = available_size
    targeted_section.virtual_size = targeted_section.virtual_size + section_append_length
    section_content_placeholder = list(targeted_section.content)
    for section_append_count in range(section_append_length):
        section_content_placeholder.append(random.randint(0, 255))
    targeted_section.content = section_content_placeholder

    print('\n')
    print(targeted_section)  # .rsrc
    hexlist = []
    for c in list(targeted_section.content):
        hexlist.append(hex(c))
    print(hexlist)
    print('\n\n\n')
    print(available_size)
    # print(L)
    print(fbytes)

    return fparsed


def lastindex(bytelist):
    for i in range(len(bytelist) - 1, 0, -1):
        if bytelist[i] != 0:
            return i + 1
    return -1


def pert_inject_random_codecave(fbytes):
    fparsed = lief.parse(fbytes)
    tsection = random.choice(fparsed.sections)
    content = list(tsection.content)
    start_index = random.randrange(0, len(content))
    end_index = random.randrange(start_index + 1, len(content))
    for i in range(start_index, end_index + 1):
        content[i] = random.randrange(0, 256)
    tsection.content = content
    hexlist = []
    for c in content:
        hexlist.append(hex(c))
    print('\n')
    print(hexlist)
    print('\n\n')
    print(start_index)
    print(end_index)
    return fparsed


def pert_upx_pack(fbytes, seed=None):
    nfbytes = bytes(fbytes);
    tmpfilename = os.getcwd() + "/sample/upx/origin"
    options = ['--force', '--overlay=copy'];
    compression_level = random.randint(1, 9);
    options += ['-{}'.format(compression_level)];
    options += ['--compress-exports={}'.format(random.randint(0, 1))]
    options += ['--compress-icons={}'.format(random.randint(0, 3))]
    options += ['--compress-resources={}'.format(random.randint(0, 1))]
    options += ['--strip-relocs={}'.format(random.randint(0, 1))]
    with open(os.devnull, 'w') as DEVNULL:
        retcode = subprocess.call(['upx-ucl'] + options + [tmpfilename, '-o',
                                                           tmpfilename.replace("origin", "origin_packed")],
                                  stdout=DEVNULL, stderr=DEVNULL)

    os.unlink(tmpfilename)

    if retcode == 0:  # successfully packed
        with open(tmpfilename.replace("origin", "origin_packed"), 'rb') as infile:
            nfbytes = infile.read()

        os.unlink(tmpfilename.replace("origin", "origin_packed"))

    # fparsed = lief.parse(nfbytes)

    return nfbytes


def pert_upx_unpack(fbytes, seed=None):
    nfbytes = bytes(fbytes);
    tmpfilename = os.getcwd() + "/sample/upx/origin_packed"
    with open(os.devnull, 'w') as DEVNULL:
        retcode = subprocess.call(['upx-ucl'] + [tmpfilename, '-d', '-o',
                                                 tmpfilename.replace("origin_packed", "origin_unpacked")],
                                  stdout=DEVNULL, stderr=DEVNULL)
    os.unlink(tmpfilename)
    if retcode == 0:  # successfully packed
        with open(tmpfilename.replace("origin", "origin_packed"), 'rb') as infile:
            nfbytes = infile.read()
        os.unlink(tmpfilename.replace("origin", "origin_packed"))
    return nfbytes


def upx_print():
    filename1 = "D:\\AutoGenMalware\\Malware_Database\\packed\\VirusShare_1e34b50b8af8dbeb750c291981428053"
    filename2 = "D:\\AutoGenMalware\\Malware_Database\\packed\\origin_packed"
    filename2 = "D:\\AutoGenMalware\\Malware_Database\\packed\\origin_unpacked"
    filename1 = "D:\\AutoGenMalware\\Malware_Database\\packed\\origin_packed"
    fbytes = open(filename1, "rb").read()
    fparsed = lief.parse(fbytes)
    for section in fparsed.sections:
        print(section)
    print('\n')

    fbytes = open(filename2, "rb").read()
    fparsed = lief.parse(fbytes)
    for section in fparsed.sections:
        print(section)

def ELF_overlay_append(fbytes, seed=None):
    random.seed(seed)
    l = 2 ** random.randint(5, 8)
    upper = random.randrange(128)
    new_fbytes = fbytes + bytes([random.randint(0, upper) for _ in range(l)])
    new_fparsed = lief.parse(new_fbytes)
    return new_fparsed

def imports_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    libname = random.choice(list(COMMON_IMPORTS.keys()))
    funcname = random.choice(list(COMMON_IMPORTS[libname]))
    lowerlibname = libname.lower()

    # printing libraries before perturbation
    i = 1
    for im in fparsed.imports:
        # print(im.name)
        e_list=[]
        for e in im.entries:
            e_list.append(e.name)
        print('Imported library', str(i) + ':', im.name, e_list)
        i = i + 1

    lib = None
    for im in fparsed.imports:
        if im.name.lower() == lowerlibname:
            lib = im
            break
    if lib is None:
        lib = fparsed.add_library(libname)

    names = set([e.name for e in lib.entries])
    if not funcname in names:
        lib.add_entry(funcname)

    # printing libraries before perturbation
    print('-------------')
    i = 1
    for im in fparsed.imports:
        e_list = []
        for e in im.entries:
            e_list.append(e.name)
        print('Imported library', str(i) + ':', im.name, e_list)
        i = i + 1


    return fparsed

def pert_DLL_characteristics(fbytes):
    fparsed = lief.parse(fbytes)
    print(fparsed.optional_header.dll_characteristics_lists)
    chlist = [lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA,
              lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE,
              lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY,
              lief.PE.DLL_CHARACTERISTICS.NX_COMPAT,
              lief.PE.DLL_CHARACTERISTICS.NO_ISOLATION,
              lief.PE.DLL_CHARACTERISTICS.NO_SEH,
              lief.PE.DLL_CHARACTERISTICS.NO_BIND,
              lief.PE.DLL_CHARACTERISTICS.APPCONTAINER,
              lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER,
              lief.PE.DLL_CHARACTERISTICS.GUARD_CF,
              lief.PE.DLL_CHARACTERISTICS.TERMINAL_SERVER_AWARE]
    filteredChList = []
    for ch in chlist:
        if ch not in fparsed.optional_header.dll_characteristics_lists:
            filteredChList.append(ch)

    index = random.randint(0, len(filteredChList)-1)
    if index >= 0:
    # //dll_characteristics_lists
         fparsed.optional_header.add(chlist[index])

    print(fparsed.optional_header.dll_characteristics_lists)

    return fparsed


def pert_test():
    peFolder = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/'
    elfFolder = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/'
    filename = "/home/infobeyond/workspace/VirusShare/VirusShare_PE"
    # filename = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/VirusShare_000a86a05b6208c3053ead8d1193b863'

    files = os.listdir(peFolder)
    i = 0
    for f in files:
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
        filename = peFolder + f
        if lief.is_pe(filename):
            fbytes = open(filename, "rb").read()
            liefparsed = lief.parse(fbytes)
            print(liefparsed.libraries)
            # print(len(liefparsed.optional_header.dll_characteristics_lists))
            if len(liefparsed.optional_header.dll_characteristics_lists) > 0:
                # print(liefparsed.optional_header.dll_characteristics_lists)
                # print(liefparsed.optional_header)
                pert_DLL_characteristics(fbytes)
            # if(len(liefparsed.imports) == 2):
            #     print(len(liefparsed.imports))
            #     print(list(liefparsed.imports))
            #     for im in liefparsed.imports:
            #         # print(im.name)
            #         print(len(im.entries))
            #         for entry in im.entries:
            #             print(entry.name)
            #         print('---')

            # imports_append(fbytes)
            break
            print('---------------------------------------------------------')
            i = i + 1
            pass

    files = os.listdir(elfFolder)
    i = 0
    for f in files:
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
        filename = elfFolder + f
        if lief.is_elf(filename):
            fbytes = open(filename, "rb").read()
            # pert_inject_random_codecave(fbytes)
            # upx_print()
            # pert_rich_header(fbytes)
            liefparsed = lief.parse(fbytes)
            print(liefparsed.libraries)
            # print(testperse.concrete)
            print('---------------------------------------------------------')

def collect_ELF_Shared_Library():
    libDict = {}
    path = '/home/infobeyond/workspace/VirusShare/liblist'
    with open(path) as files:
        for f in files:
            if f.startswith('/'):
                if lief.is_elf(f.strip()):
                    print(f.strip())
                    libName = f.strip().split('/')[len(f.strip().split('/')) - 1]
                    print(libName)
                    filename = f.strip()
                    fbytes = open(filename, "rb").read()
                    liefparsed = lief.parse(fbytes)
                    funcList = []
                    for func in liefparsed.exported_functions:
                        funcList.append(func.name)
                        # print(func.name)
                    # print(funcList)
                    libDict[libName] = funcList
                    # break
    print(libDict)
    with open(os.path.join(module_path, 'elf_dll_imports.json'), 'w') as fp:
        json.dump(libDict, fp)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # pert_test()
    # jsonStr = json.dumps(myDict)
    # print(jsonStr)
    pass





# See PyCharm help at https://www.jetbrains.com/help/pycharm/
