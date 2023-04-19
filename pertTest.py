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
import array
import r2pipe
import perturbation as p
import analysis as a

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'small_dll_imports.json'), 'r'))

ELF_COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'elf_dll_imports.json'), 'r'))

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

# new PE perturbation - 1
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

# new PE perturbation - 2
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
         fparsed.optional_header.add(chlist[index])

    print(fparsed.optional_header.dll_characteristics_lists)
    return fparsed



def elf_imports_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    # funcname = random.choice(list(ELF_COMMON_IMPORTS[libname]))
    # libname = random.choice(list(ELF_COMMON_IMPORTS.keys()))

    while True:
        libname = random.choice(list(ELF_COMMON_IMPORTS.keys()))
        if libname not in fparsed.libraries:
            fparsed.add_library(libname)
            break
    return fparsed

def elf_program_header_table(fbytes, seed=None):
    random.seed(seed)
    liefparsed = lief.parse(fbytes)

    # do not perturb if not executable
    if str(liefparsed.header.file_type) == 'E_TYPE.EXECUTABLE':
        return fbytes

    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    builder.write('/home/infobeyond/workspace/VirusShare/testElf/phtpert')

    PHT_Offset = liefparsed.header.program_header_offset
    pert_PHT_SN = random.randrange(0, liefparsed.header.numberof_segments)
    print(liefparsed.get_content_from_virtual_address(PHT_Offset,
                                                      liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
    pertAddress = liefparsed.offset_to_virtual_address(PHT_Offset + (pert_PHT_SN * liefparsed.header.program_header_size))

    r2n = r2pipe.open('/home/infobeyond/workspace/VirusShare/testElf/phtpert', ['-2', '-n','-w'])
    for x in range(liefparsed.header.program_header_size):
        # leave p_offset(4-byte), p_vaddr(4-byte), and p_paddr(4-byte) unmodified
        if x >=4 and x<=16:
            continue
        # insert random codes
        r2n.cmd("s " + str(liefparsed.offset_to_virtual_address(pertAddress+x)))
        data = str(hex(random.randrange(0, 255)))
        print(data)
        r2n.cmd("wx " + data)

    print(pertAddress)
    liefparsed = lief.parse('/home/infobeyond/workspace/VirusShare/testElf/phtpert')
    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    print(liefparsed.get_content_from_virtual_address(PHT_Offset,
                                                      liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
    return array.array('B', builder.get_build()).tobytes()

# on check
def pert_elf_section_header_table(fbytes, seed=None):
    random.seed(seed)
    liefparsed = lief.parse(fbytes)
    # do not perturb if not executable
    if str(liefparsed.header.file_type) != 'E_TYPE.EXECUTABLE' or liefparsed.header.numberof_sections == 0:
        return fbytes

    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    builder.write('/home/infobeyond/workspace/VirusShare/testElf/phtpert')

    SHT_Offset = liefparsed.header.section_header_offset
    print(liefparsed.header)
    print(SHT_Offset)
    print(hex(SHT_Offset))
    print(liefparsed.offset_to_virtual_address(SHT_Offset))

    print('image base')
    print(liefparsed.imagebase)
    print(hex(liefparsed.imagebase))

    pert_SHT_SN = random.randrange(0, liefparsed.header.numberof_sections)

    try:
        content = liefparsed.get_content_from_virtual_address(liefparsed.offset_to_virtual_address(SHT_Offset), 10)
    except:
        return fbytes


    if len(content) > 0:
        pass

    print(liefparsed.get_content_from_virtual_address(liefparsed.offset_to_virtual_address(SHT_Offset),
                                                      liefparsed.header.numberof_sections * liefparsed.header.section_header_size))
    pertAddress = liefparsed.offset_to_virtual_address(
        SHT_Offset + (pert_SHT_SN * liefparsed.header.section_header_size))

    r2n = r2pipe.open('/home/infobeyond/workspace/VirusShare/testElf/phtpert', ['-2', '-n', '-w'])
    for x in range(liefparsed.header.section_header_size):
        # leave sh_addr(4-byte) and sh_offset(4-byte) unmodified
        if x >= 12 and x <= 20:
            continue
        # insert random codes
        r2n.cmd("s " + str(pertAddress + x))
        data = str(hex(random.randrange(0, 255)))
        print(data)
        r2n.cmd("wx " + data)

    print(pertAddress)
    liefparsed = lief.parse('/home/infobeyond/workspace/VirusShare/testElf/phtpert')
    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    print(liefparsed.get_content_from_virtual_address(liefparsed.offset_to_virtual_address(SHT_Offset),
                                                      liefparsed.header.numberof_sections * liefparsed.header.section_header_size))
    return array.array('B', builder.get_build()).tobytes()

def pert_elf_section_add(fbytes, seed=None):
    fparsed = lief.parse(fbytes)
    print('----------------------------------------------')
    print('----------------------------------------------')
    for s in fparsed.sections:
        print(s)

    print('----------------------------------------------')

    length = random.randrange(1, 6)
    upper = random.randrange(128)
    L = 2 ** random.randint(5, 8)
    new_section = lief.ELF.Section("." + "".join(random.sample([chr(i) for i in range(97, 123)], length)))
    new_section.type = random.choice([lief.ELF.SECTION_TYPES.NULL, lief.ELF.SECTION_TYPES.PROGBITS, lief.ELF.SECTION_TYPES.SYMTAB, lief.ELF.SECTION_TYPES.STRTAB,
    lief.ELF.SECTION_TYPES.RELA, lief.ELF.SECTION_TYPES.HASH, lief.ELF.SECTION_TYPES.DYNAMIC, lief.ELF.SECTION_TYPES.NOTE,
    lief.ELF.SECTION_TYPES.NOBITS, lief.ELF.SECTION_TYPES.REL, lief.ELF.SECTION_TYPES.SHLIB, lief.ELF.SECTION_TYPES.DYNSYM,
    lief.ELF.SECTION_TYPES.INIT_ARRAY, lief.ELF.SECTION_TYPES.FINI_ARRAY, lief.ELF.SECTION_TYPES.PREINIT_ARRAY, lief.ELF.SECTION_TYPES.GROUP,
    lief.ELF.SECTION_TYPES.SYMTAB_SHNDX, lief.ELF.SECTION_TYPES.LOOS, lief.ELF.SECTION_TYPES.GNU_ATTRIBUTES, lief.ELF.SECTION_TYPES.GNU_HASH,
    lief.ELF.SECTION_TYPES.GNU_VERDEF, lief.ELF.SECTION_TYPES.GNU_VERNEED, lief.ELF.SECTION_TYPES.HIOS, lief.ELF.SECTION_TYPES.ANDROID_REL,
    lief.ELF.SECTION_TYPES.ANDROID_RELA, lief.ELF.SECTION_TYPES.LLVM_ADDRSIG, lief.ELF.SECTION_TYPES.RELR, lief.ELF.SECTION_TYPES.ARM_EXIDX,
    lief.ELF.SECTION_TYPES.ARM_PREEMPTMAP, lief.ELF.SECTION_TYPES.ARM_ATTRIBUTES, lief.ELF.SECTION_TYPES.ARM_DEBUGOVERLAY, lief.ELF.SECTION_TYPES.ARM_OVERLAYSECTION,
    lief.ELF.SECTION_TYPES.LOPROC, lief.ELF.SECTION_TYPES.X86_64_UNWIND, lief.ELF.SECTION_TYPES.HIPROC, lief.ELF.SECTION_TYPES.LOUSER, lief.ELF.SECTION_TYPES.HIUSER])
    new_section.content = [random.randint(0, upper) for _ in range(L)]
    new_section.alignment = 8
    fparsed.add(new_section, False)

    for s in fparsed.sections:
        print(s)

    return fparsed


def pert_elf_segment_add(fbytes, seed=None):
    fparsed = lief.parse(fbytes)
    print('----------------------------------------------')
    print('----------------------------------------------')
    for s in fparsed.segments:
        print(s)
    print('----------------------------------------------')
    length = random.randrange(1, 6)
    upper = random.randrange(128)
    L = 2 ** random.randint(5, 8)
    new_segment = lief.ELF.Segment()

    new_segment.add(random.choice([lief.ELF.SEGMENT_FLAGS.NONE,
                                   lief.ELF.SEGMENT_FLAGS.X, lief.ELF.SEGMENT_FLAGS.W, lief.ELF.SEGMENT_FLAGS.R]))
    new_segment.type = random.choice([lief.ELF.SEGMENT_TYPES.NULL, lief.ELF.SEGMENT_TYPES.LOAD, lief.ELF.SEGMENT_TYPES.DYNAMIC, lief.ELF.SEGMENT_TYPES.INTERP,
    lief.ELF.SEGMENT_TYPES.NOTE, lief.ELF.SEGMENT_TYPES.SHLIB, lief.ELF.SEGMENT_TYPES.PHDR, lief.ELF.SEGMENT_TYPES.TLS,
    lief.ELF.SEGMENT_TYPES.GNU_EH_FRAME, lief.ELF.SEGMENT_TYPES.GNU_PROPERTY, lief.ELF.SEGMENT_TYPES.GNU_STACK, lief.ELF.SEGMENT_TYPES.GNU_RELRO,
    lief.ELF.SEGMENT_TYPES.ARM_ARCHEXT, lief.ELF.SEGMENT_TYPES.ARM_UNWIND, lief.ELF.SEGMENT_TYPES.UNWIND])
    new_segment.content = [random.randint(0, upper) for _ in range(L)]
    new_segment.alignment = 8
    fparsed.add(new_segment)

    for s in fparsed.segments:
        print(s)

    return fparsed

def pert_elf_segment_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    targeted_segment = random.choice(fparsed.segments)
    L = 2 ** random.randint(5, 8)
    available_size = targeted_segment.physical_size - len(targeted_segment.content)

    if targeted_segment.virtual_size <= targeted_segment.physical_size:
        targeted_segment.virtual_size = targeted_segment.physical_size
    else:
        targeted_segment.physical_size = (int(targeted_segment.virtual_size / 512) + 1) * 512

    # print (targeted_section.name)

    if L > available_size:
        L = available_size

    upper = random.randrange(128)  # it was 256
    temp = list(targeted_segment.content)
    temp.append(1)
    # temp = temp + [random.randint(0, upper) for _ in range(L)]
    targeted_segment.content = temp

    return fparsed

def pert_test():
    # peFolder = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/'
    # elfFolder = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/'

    peFolder = '/home/infobeyond/workspace/VirusShare/peMalwares/'
    elfFolder = '/home/infobeyond/workspace/VirusShare/testElf/'

    filename = "/home/infobeyond/workspace/VirusShare/VirusShare_PE"
    # filename = '/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/elfMalwares/VirusShare_000a86a05b6208c3053ead8d1193b863'

    # files = os.listdir(peFolder)
    # i = 0
    # for f in files:
    #     print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
    #     filename = peFolder + f
    #     if lief.is_pe(filename):
    #         fbytes = open(filename, "rb").read()
    #         liefparsed = lief.parse(fbytes)
    #         print(liefparsed.libraries)
    #         # print(len(liefparsed.optional_header.dll_characteristics_lists))
    #         if len(liefparsed.optional_header.dll_characteristics_lists) > 0:
    #             # print(liefparsed.optional_header.dll_characteristics_lists)
    #             # print(liefparsed.optional_header)
    #             pert_DLL_characteristics(fbytes)
    #         # if(len(liefparsed.imports) == 2):
    #         #     print(len(liefparsed.imports))
    #         #     print(list(liefparsed.imports))
    #         #     for im in liefparsed.imports:
    #         #         # print(im.name)
    #         #         print(len(im.entries))
    #         #         for entry in im.entries:
    #         #             print(entry.name)
    #         #         print('---')
    #
    #         # imports_append(fbytes)
    #         break
    #         print('---------------------------------------------------------')
    #         i = i + 1
    #         pass

    files = os.listdir(elfFolder)
    i = 0
    for f in files:
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
        f = 'VirusShare_4929aaa4badb19de127202fab1bd4747'
        filename = elfFolder + f
        print(filename)
        if lief.is_elf(filename):
            fbytes = open(filename, "rb").read()

            newfbytes = p.elf_section_add(fbytes)
            pert_elf_section_header_table(newfbytes)
            fparsed = lief.parse(newfbytes)
            fparsed.write(filename + '_Pert')

            # pert_elf_segment_append(fbytes)
            # pert_elf_segment_add(fbytes)
            # pert_elf_section_add(fbytes)
            # pert_elf_section_header_table(fbytes)
            # # pert_elf_program_header_table(fbytes)
            # # pert_inject_random_codecave(fbytes)
            # # upx_print()
            # # pert_rich_header(fbytes)
            # liefparsed = lief.parse(fbytes)
            # # print(liefparsed.concrete)
            #
            # for seg in liefparsed.segments:
            #     print(seg)
            #
            # print(liefparsed.header)
            # print(liefparsed.header.program_header_offset)
            # print(liefparsed.header.program_header_size)
            # print(liefparsed.header.numberof_segments)
            # print('----------------------------------')
            # print(liefparsed.header.section_header_offset)
            # print(liefparsed.header.section_header_size)
            # print(liefparsed.header.numberof_sections)
            # print(liefparsed.header.file_type)
            #
            # PHT_address = liefparsed.offset_to_virtual_address(liefparsed.header.program_header_offset)
            # print (liefparsed.offset_to_virtual_address(liefparsed.header.program_header_offset))
            # print(liefparsed.get_content_from_virtual_address(PHT_address, liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
            #
            #
            # liefparsed.patch_address(PHT_address, [0x4])
            #
            # print(liefparsed.get_content_from_virtual_address(PHT_address,
            #                                                   liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
            #
            # builder = lief.ELF.Builder(liefparsed)
            # # builder.build_imports(True)
            # # builder.patch_imports(True)
            #
            # # print(builder.config_t)
            #
            # builder.build()
            # liefparsed.write('/home/infobeyond/workspace/VirusShare/testElf/phtpert1')
            #
            # newfbytes = array.array('B', builder.get_build()).tobytes()
            # newliefparsed = lief.parse(newfbytes)
            #
            #
            # print(newliefparsed.get_content_from_virtual_address(newliefparsed.offset_to_virtual_address(newliefparsed.header.program_header_offset),
            #                                                   newliefparsed.header.numberof_segments * newliefparsed.header.program_header_size))
            #
            #
            #
            #
            # print(hex(liefparsed.imagebase))
            #
            #
            # # va = liefparsed.offset_to_virtual_address(82)
            # #
            # # va1 = liefparsed.offset_to_virtual_address(0x33172)
            # #
            # # print(hex(va))
            # # print(hex(va1))
            # #
            # # PHT = liefparsed.get_content_from_virtual_address(32850, 10000)
            # #
            # # PHTHex=[]
            # # for en in PHT:
            # #     PHTHex.append(hex(en))
            # # print(PHTHex)
            # # print(liefparsed.get_content_from_virtual_address(32850, 10000))
            # # print(liefparsed.libraries)
            #
            # # liefparsed.add_library('libcaca.so.0')
            # # liefparsed.add_exported_function()
            # print('-----------')
            #
            # # for func in liefparsed.imported_functions:
            # #     print(func.name)
            # #     print(func.address)
            # #
            # # if len(liefparsed.libraries) > 0:
            # #     print(liefparsed.libraries)
            # #     print('---------------------------------------------------------')
            # print(liefparsed.imported_functions)
            # print(liefparsed.libraries)
            # if len(liefparsed.libraries) > 0:
            #     print(liefparsed.get_library(liefparsed.libraries[0]))
            #
            #
            break
            i = i + 1

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


def jottiVirusScanTest():
    # elfMal = '/home/infobeyond/workspace/VirusShare/testElf/VirusShare_4929aaa4badb19de127202fab1bd4747'
    # fbytes = open(elfMal, "rb").read()
    # scanJobId = a.send_v2_jotti_scan(fbytes)
    # jotti_result, jotti_report = a.jotti_v2_analysis(scanJobId)
    # print(jotti_result)
    # print(jotti_report)
    elfFolder = '/home/infobeyond/workspace/VirusShare/elfMalwares/'
    files = os.listdir(elfFolder)
    i = 0
    scanJobIds = []
    for f in files:
        if i > 20:
            break
        print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %):" + str(f))
        filename = elfFolder + f
        fbytes = open(filename, "rb").read()
        scanJobId = a.send_v2_jotti_scan(fbytes)
        scanJobIds.append(scanJobId)
        i = i + 1

    for scanJobId in scanJobIds:
        jotti_result, jotti_report = a.jotti_v2_analysis(scanJobId)
        print('Scan result for id '+str(scanJobId))
        print(jotti_result)
        print(jotti_report)
        print('-----------------------------------')
    pass

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # pert_test()
    # jsonStr = json.dumps(myDict)
    # print(jsonStr)
    # pert_test()
    # jottiVirusScanTest()

    elfFolder = '/home/infobeyond/workspace/VirusShare/elfMalwares/'
    savedFile = '/home/infobeyond/workspace/VirusShare/elfMalwaresList'
    files = os.listdir(elfFolder)
    i = 0
    scanJobIds = []
    for f in files:
        print(str("'")+f+str("'")+str(','))
        pass

    pass


# See PyCharm help at https://www.jetbrains.com/help/pycharm/